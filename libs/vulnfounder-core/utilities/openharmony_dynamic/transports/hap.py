"""HAP 传输层 v2（§9.1 / R8）。

模板参数化：Index.ets 模板占位符 ← 契约 protocol.field_values + entry.endpoint。
构建 → 签名 → 安装 → 启动 → （观测由外层负责）→ force-stop → 卸载。
bundle 名固定为签名 profile 允许的 com.security.research.trigger。
"""

from __future__ import annotations

import os
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import INPUT_DELIVERED, INPUT_NOT_SENT, SendResult, TransportError
from ..toolchain import toolchain_root

if TYPE_CHECKING:
    from ..hdc_client import HDCClient

_PROJECT_ROOT = Path(__file__).resolve().parents[5]
_SUITE_DIR = _PROJECT_ROOT / "assets" / "dynamic_tester" / "hap_poc_suite"
_TEMPLATE_PROJECT = _SUITE_DIR / "dp01_hap"
_TEMPLATE_INDEX = _SUITE_DIR / "HAP_INDEX.ets.in"

# Toolchain and signing credentials are deployment inputs.  The previous
# implementation embedded one developer's home-directory certificate path,
# which made a copied checkout unusable on another machine and risked leaking
# a private signing location into reports.
_TOOLCHAIN_ROOT = toolchain_root()
_HVIGORW = _TOOLCHAIN_ROOT / "hvigor/bin/hvigorw"
_NODE = _TOOLCHAIN_ROOT / "tool/node"
_SIGN_JAR = _TOOLCHAIN_ROOT / "sdk/default/openharmony/toolchains/lib/hap-sign-tool.jar"
_HDC = _TOOLCHAIN_ROOT / "sdk/default/openharmony/toolchains/hdc"
_SDK_SIGNING_LIB = _TOOLCHAIN_ROOT / "sdk/default/openharmony/toolchains/lib"
_SDK_SIGNING_P12 = _SDK_SIGNING_LIB / "OpenHarmony.p12"
_SDK_PROFILE_ROOT_CERT = _SDK_SIGNING_LIB / "OpenHarmonyProfileDebug.pem"
_JAVA = os.environ.get("VULNFOUNDER_JAVA", "").strip() or shutil.which("java") or "java"
_KEYTOOL = os.environ.get("VULNFOUNDER_KEYTOOL", "").strip() or shutil.which("keytool") or "keytool"
_SDK_SIGNING_PASSWORD = "123456"

_CERT_DIR_ENV = "VULNFOUNDER_HAP_CERT_DIR"
CERT_DIR = Path(os.environ[_CERT_DIR_ENV]).expanduser().resolve() if os.environ.get(_CERT_DIR_ENV) else (
    _PROJECT_ROOT / "config" / "hap_cert"
)
KEY_ALIAS = "oh-release-key"
KEY_PWD = "123456"
BUNDLE_NAME = "com.security.research.trigger"
ABILITY_NAME = "EntryAbility"

# Index.ets 模板占位符 → field_values 键（通用映射，非样本硬编码）
_PLACEHOLDER_MAP = {
    "__TARGET__": "target",
    "__MODE__": "mode",
    "__HOST__": "host",
    "__PORT__": "port",
    "__LOCAL_PATH__": "local_path",
    "__MARKER__": "marker",
    "__FIRST__": "first",
    "__SECOND__": "second",
    "__THIRD__": "third",
}


def _select_signing_material() -> tuple[Path, Path, Path, str, str, str] | None:
    """选择本机签名材料，不把 debug 材料伪装成 release 证书。

    交付包可带有研究用途的 ``config/hap_cert/debug`` 三件套；它只在没有
    release 三件套时作为明确的 debug profile 使用。返回值包含证书链、
    profile、P12、alias、密码和 profile 名，调用方会把 profile 写入构建
    日志/产物元数据但绝不写出密码。
    """

    release = (
        CERT_DIR / "oh_release_chain.cer",
        CERT_DIR / "oh_profile8.p7b",
        CERT_DIR / "oh_release.p12",
        "oh-release-key",
        "123456",
        "release",
    )
    if all(path.is_file() for path in release[:3]):
        return release
    # Debug profile 必须显式选择。不同 OpenHarmony 版本/开发板的 debug
    # profile 不一定兼容当前 hap-sign-tool，自动选用会把“证书无效”伪装成
    # 动态测试失败；默认要求用户提供匹配设备的 release 材料。
    if os.environ.get("VULNFOUNDER_HAP_CERT_PROFILE", "").strip().lower() != "debug":
        return None
    debug_dir = CERT_DIR / "debug"
    debug = (
        debug_dir / "app-cert.pem",
        debug_dir / "debug-profile.p7b",
        debug_dir / "debug.p12",
        "debugKey",
        "00000000000000000000000000000000",
        "debug",
    )
    if all(path.is_file() for path in debug[:3]):
        return debug
    return None


def _run_sign_tool(arguments: list[str], *, timeout: int = 120) -> str:
    """运行 SDK 签名工具并返回输出；命令参数不包含可持久化的报告密钥。"""

    completed = subprocess.run(
        [_JAVA, "-jar", str(_SIGN_JAR), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        timeout=timeout,
        check=False,
    )
    output = completed.stdout.decode("utf-8", errors="replace")
    if completed.returncode != 0:
        raise TransportError("OpenHarmony 签名工具执行失败：" + output[-1800:])
    return output


def _run_keytool(arguments: list[str], *, timeout: int = 60) -> str:
    """导出公开证书链；私钥和密码只在子进程参数中短暂存在，不写入日志。"""

    completed = subprocess.run(
        [_KEYTOOL, *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        timeout=timeout,
        check=False,
    )
    output = completed.stdout.decode("utf-8", errors="replace")
    if completed.returncode != 0:
        raise TransportError("keytool 导出 OpenHarmony 证书失败：" + output[-1200:])
    return output


def _safe_signing_alias(prefix: str, contract_id: str) -> str:
    digest = hashlib.sha256(str(contract_id).encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"vf-{prefix}-{digest}"


def _generate_sdk_debug_signing_material(
    out_dir: Path,
    *,
    device_serial: str,
    contract_id: str,
) -> tuple[Path, Path, Path, str, str, str]:
    """用工具链随附的测试根密钥为当前设备生成一次性 debug 签名材料。

    OpenHarmony debug profile 含设备 ID，不能把某台开发板的 p7b 固定放进
    项目。SDK 自带的 ``OpenHarmony.p12`` 是公开测试材料；这里复制到本次
    隔离目录，生成新的 app/profile 链和绑定当前 serial 的 profile，完成后
    随契约临时目录清理。生产/用户证书仍优先走 ``_select_signing_material``。
    """

    serial = str(device_serial or "").strip()
    if not serial:
        raise TransportError("无法自动生成 HAP profile：HDC 设备 serial 为空")
    required = (_SIGN_JAR, _SDK_SIGNING_P12, _SDK_PROFILE_ROOT_CERT)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise TransportError("项目内 SDK 测试签名材料不完整：" + ", ".join(missing))
    if shutil.which(_JAVA) is None and not Path(_JAVA).is_file():
        raise TransportError("无法自动生成 HAP profile：未找到 Java（可设置 VULNFOUNDER_JAVA）")
    if shutil.which(_KEYTOOL) is None and not Path(_KEYTOOL).is_file():
        raise TransportError("无法自动生成 HAP profile：未找到 keytool（可设置 VULNFOUNDER_KEYTOOL）")

    generated = out_dir / "sdk-debug-signing"
    generated.mkdir(parents=True, exist_ok=True)
    generated.chmod(0o700)
    keystore = generated / "vulnfounder-sdk-debug.p12"
    shutil.copy2(_SDK_SIGNING_P12, keystore)
    keystore.chmod(0o600)

    password = _SDK_SIGNING_PASSWORD
    app_alias = _safe_signing_alias("app", contract_id)
    profile_ca_alias = _safe_signing_alias("profile-ca", contract_id)
    profile_alias = _safe_signing_alias("profile", contract_id)
    common = ["-keystoreFile", str(keystore), "-keystorePwd", password]
    _run_sign_tool([
        "generate-keypair", "-keyAlias", app_alias, "-keyPwd", password,
        "-keyAlg", "ECC", "-keySize", "NIST-P-256", *common,
    ])
    _run_sign_tool([
        "generate-cert", "-keyAlias", app_alias, "-keyPwd", password,
        "-issuer", "C=CN,O=OpenHarmony,OU=OpenHarmony Team,CN=OpenHarmony Application CA",
        "-issuerKeyAlias", "openharmony application ca", "-issuerKeyPwd", password,
        "-subject", "C=CN,O=VulnFounder,OU=Research,CN=VulnFounder App Debug",
        "-validity", "3650", "-keyUsage", "digitalSignature", "-extKeyUsage", "codeSignature",
        "-signAlg", "SHA256withECDSA", *common, "-issuerKeystoreFile", str(keystore),
        "-issuerKeystorePwd", password, "-outFile", str(generated / "app-cert.cer"),
    ])
    _run_sign_tool([
        "generate-keypair", "-keyAlias", profile_ca_alias, "-keyPwd", password,
        "-keyAlg", "ECC", "-keySize", "NIST-P-256", *common,
    ])
    _run_sign_tool([
        "generate-ca", "-keyAlias", profile_ca_alias, "-keyPwd", password,
        "-keyAlg", "ECC", "-keySize", "NIST-P-256",
        "-issuer", "C=CN,O=OpenHarmony,OU=OpenHarmony Team,CN=OpenHarmony Application Root CA",
        "-issuerKeyAlias", "openharmony application root ca", "-issuerKeyPwd", password,
        "-subject", "C=CN,O=VulnFounder,OU=Research,CN=VulnFounder Profile CA",
        "-validity", "3650", "-signAlg", "SHA384withECDSA", "-basicConstraintsPathLen", "1",
        *common, "-issuerKeystoreFile", str(keystore), "-issuerKeystorePwd", password,
        "-outFile", str(generated / "profile-ca.cer"),
    ])
    _run_sign_tool([
        "generate-keypair", "-keyAlias", profile_alias, "-keyPwd", password,
        "-keyAlg", "ECC", "-keySize", "NIST-P-256", *common,
    ])
    _run_sign_tool([
        "generate-cert", "-keyAlias", profile_alias, "-keyPwd", password,
        "-issuer", "C=CN,O=VulnFounder,OU=Research,CN=VulnFounder Profile CA",
        "-issuerKeyAlias", profile_ca_alias, "-issuerKeyPwd", password,
        "-subject", "C=CN,O=VulnFounder,OU=Research,CN=VulnFounder Profile Debug",
        "-validity", "3650", "-keyUsage", "digitalSignature", "-extKeyUsage", "codeSignature",
        "-signAlg", "SHA256withECDSA", *common, "-issuerKeystoreFile", str(keystore),
        "-issuerKeystorePwd", password, "-outFile", str(generated / "profile-cert.cer"),
    ])

    root_cert = generated / "root.cer"
    app_ca_cert = generated / "app-ca.cer"
    _run_keytool([
        "-exportcert", "-rfc", "-keystore", str(keystore), "-storetype", "PKCS12",
        "-storepass", password, "-alias", "openharmony application root ca", "-file", str(root_cert),
    ])
    _run_keytool([
        "-exportcert", "-rfc", "-keystore", str(keystore), "-storetype", "PKCS12",
        "-storepass", password, "-alias", "openharmony application ca", "-file", str(app_ca_cert),
    ])
    app_chain = generated / "app-chain.cer"
    profile_chain = generated / "profile-chain.cer"
    app_chain.write_text(
        (generated / "app-cert.cer").read_text(encoding="utf-8")
        + app_ca_cert.read_text(encoding="utf-8")
        + root_cert.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    profile_chain.write_text(
        (generated / "profile-cert.cer").read_text(encoding="utf-8")
        + (generated / "profile-ca.cer").read_text(encoding="utf-8")
        + root_cert.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    template = _SDK_SIGNING_LIB / "UnsgnedDebugProfileTemplate.json"
    if not template.is_file():
        raise TransportError("项目内 SDK 缺少 UnsgnedDebugProfileTemplate.json")
    profile_json = generated / "profile.json"
    profile_data = json.loads(template.read_text(encoding="utf-8"))
    profile_data["validity"] = {
        "not-before": int(time.time()) - 3600,
        "not-after": int(time.time()) + 3650 * 24 * 3600,
    }
    profile_data.setdefault("bundle-info", {})["bundle-name"] = BUNDLE_NAME
    profile_data["bundle-info"]["development-certificate"] = app_chain.read_text(encoding="utf-8")
    profile_data.setdefault("debug-info", {})["device-ids"] = [serial]
    profile_json.write_text(json.dumps(profile_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    signed_profile = generated / "debug-profile.p7b"
    _run_sign_tool([
        "sign-profile", "-mode", "localSign", "-keyAlias", profile_alias,
        "-keyPwd", password, "-profileCertFile", str(profile_chain),
        "-inFile", str(profile_json), "-signAlg", "SHA256withECDSA",
        *common, "-outFile", str(signed_profile),
    ])
    verification = _run_sign_tool(["verify-profile", "-inFile", str(signed_profile)])
    if '"verifiedPassed": true' not in verification:
        raise TransportError("自动生成的 HAP profile 未通过 SDK 校验：" + verification[-1200:])
    return app_chain, signed_profile, keystore, app_alias, password, "sdk-generated-debug"


def _escape_arkts_string(value: str) -> str:
    """转义插入单引号 ArkTS 字符串字面量的运行时值。

    协议帧、路径和 marker 都由当前契约/模型提供，不能假设只包含字母数字。
    直接替换到 ``'...'`` 中会让 ``printf '%s'``、反斜杠或换行破坏 HAP
    工程的 ArkTS 语法，表现为 hvigor 没有产出 unsigned HAP。这里仅编码
    字符串字面量，不修改运行时还原后的报文内容。
    """
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


class HapTransport:
    transport_id = "hap"

    def __init__(self, hdc: "HDCClient", *, work_root: Path | None = None) -> None:
        self.hdc = hdc
        self.work_root = work_root or Path(tempfile.gettempdir())
        self._installed_bundle: str | None = None

    # ------------------------------------------------------------------
    def build(
        self,
        field_values: dict[str, Any],
        *,
        contract_id: str,
        frame_interval_seconds: float = 0.3,
    ) -> Path:
        """模板参数化 → hvigor 构建 → hap-sign-tool 签名，返回 signed.hap 路径。"""
        for required in ("mode", "host", "port", "target"):
            if not str(field_values.get(required, "") or "").strip():
                raise TransportError(f"HAP 传输缺少 field_values[{required!r}]")
        if not _TEMPLATE_PROJECT.exists() or not _TEMPLATE_INDEX.exists():
            raise TransportError(f"HAP 模板缺失: {_TEMPLATE_PROJECT}")
        out_dir = self.work_root / f"vf-hap-{contract_id}"
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)
        signing_material = _select_signing_material()
        if signing_material is None:
            # 没有用户导入的 release/debug 三件套时，优先使用项目内 SDK
            # 的公开测试根密钥为当前 HDC serial 生成设备绑定 profile。
            # 这样新机器无需手动寻找 p7b；生成结果仍只存在本次隔离目录。
            try:
                signing_material = _generate_sdk_debug_signing_material(
                    out_dir,
                    device_serial=str(getattr(self.hdc, "serial", "") or ""),
                    contract_id=contract_id,
                )
            except TransportError as auto_error:
                required_certs = (
                    CERT_DIR / "oh_release_chain.cer",
                    CERT_DIR / "oh_profile8.p7b",
                    CERT_DIR / "oh_release.p12",
                )
                missing_certs = [str(path) for path in required_certs if not path.is_file()]
                raise TransportError(
                    "HAP 签名材料缺失，且项目内 SDK 自动生成 debug profile 失败；请设置 "
                    "VULNFOUNDER_HAP_CERT_DIR，或检查项目工具链/Java/HDC："
                    + ", ".join(missing_certs)
                    + f"。自动生成失败原因：{auto_error}"
                ) from auto_error
        app_cert, profile, keystore, key_alias, key_pwd, _profile_name = signing_material
        project = out_dir / "project"
        # 排除历史构建产物（build*.log / build 目录）与签名物，但保留 build-profile.json5
        shutil.copytree(_TEMPLATE_PROJECT, project,
                        ignore=shutil.ignore_patterns(".hvigor", "build", "signing", "*.log"))
        # Hvigor 的 OpenHarmony signingConfigs 仍需要看到 profile 和
        # keystore。签名材料只复制到本次隔离构建目录，构建完成后随临时
        # 工作目录一起清理；不会把私钥写入模板或报告。
        signing_dir = project / "signing"
        signing_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(app_cert, signing_dir / "app-cert.pem")
        shutil.copy2(profile, signing_dir / "debug-profile.p7b")
        shutil.copy2(keystore, signing_dir / "debug.p12")

        # 模板默认使用 SDK 调试材料的 alias/password。导入正式材料后，
        # Hvigor 仍会先读取 build-profile.json5；如果不随材料更新，
        # 外部 sign-app 参数虽然正确，Hvigor 仍可能在构建阶段先失败。
        # 只修改本次隔离工程，不触碰项目模板和用户证书目录。
        profile_path = project / "build-profile.json5"
        if profile_path.is_file():
            profile_text = profile_path.read_text(encoding="utf-8")
            profile_text = profile_text.replace('"keyAlias": "debugKey"', f'"keyAlias": {key_alias!r}')
            profile_text = profile_text.replace('"keyPassword": "00000000000000000000000000000000"', f'"keyPassword": {key_pwd!r}')
            profile_text = profile_text.replace('"storePassword": "00000000000000000000000000000000"', f'"storePassword": {key_pwd!r}')
            profile_path.write_text(profile_text, encoding="utf-8")

        index_src = _TEMPLATE_INDEX.read_text(encoding="utf-8")
        for placeholder, key in _PLACEHOLDER_MAP.items():
            value = _escape_arkts_string(str(field_values.get(key, "")))
            index_src = index_src.replace(placeholder, value)
        # PORT 在模板中是数值表达式而不是字符串字面量；严格规整为整数，
        # 防止模型/上游输入把任意文本拼进 ArkTS 源码。
        raw_port = field_values.get("port", "")
        if isinstance(raw_port, bool):
            raise TransportError("HAP 传输 field_values['port'] 必须是整数")
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise TransportError("HAP 传输 field_values['port'] 必须是整数") from exc
        if not 1 <= port <= 65535:
            raise TransportError("HAP 传输 field_values['port'] 超出 1..65535")
        index_src = index_src.replace("__PORT__", str(port))
        try:
            delay_ms = int(round(float(frame_interval_seconds) * 1000.0))
        except (TypeError, ValueError) as exc:
            raise TransportError("HAP 帧间隔必须是数字") from exc
        if delay_ms < 0 or delay_ms > 600000:
            raise TransportError("HAP 帧间隔必须在 0..600 秒之间")
        index_src = index_src.replace("__FRAME_DELAY_MS__", str(delay_ms))
        index_path = project / "Entry/src/main/ets/pages/Index.ets"
        index_path.write_text(index_src, encoding="utf-8")

        (project / "local.properties").write_text(
            f"sdk.dir={_TOOLCHAIN_ROOT / 'sdk'}\nnodejs.dir={_NODE}\n", encoding="utf-8"
        )

        # Hvigor 默认把全局缓存写到 ``$HOME/.hvigor``。在 Web/批量运行中，
        # 该目录可能属于另一个用户、被系统策略设为只读，或者被多个并发
        # 构建共享，最终表现为 HAP 尚未开始编译就因 EPERM 失败。把缓存
        # 绑定到本次契约的隔离工作目录：
        #   * 不修改宿主机用户目录；
        #   * 不让不同样本共享项目缓存；
        #   * build log 中可以根据 out_dir 复现同一份输入。
        # Hvigor 6.23 的官方入口是 HVIGOR_USER_HOME，而不是仅设置 HOME。
        hvigor_user_home = out_dir / ".hvigor-user"
        hvigor_user_home.mkdir(parents=True, exist_ok=True)
        self._stage_offline_hvigor_dependencies(project, hvigor_user_home)
        env = {
            **dict(os.environ),
            "NODE_HOME": str(_NODE),
            "HVIGOR_USER_HOME": str(hvigor_user_home),
        }
        build = subprocess.run(
            [str(_HVIGORW), "assembleApp", "--no-daemon"],
            cwd=str(project),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            timeout=600,
            check=False,
        )
        (out_dir / "hvigor-build.log").write_bytes(build.stdout)
        unsigned = sorted(project.rglob("entry-default-unsigned.hap"))
        if not unsigned:
            raise TransportError(
                "hvigor 未产出 unsigned HAP，日志尾部:\n"
                + build.stdout.decode("utf-8", errors="replace")[-1500:]
            )

        signed = out_dir / "entry-default-signed.hap"
        sign_cmd = [
            _JAVA, "-jar", str(_SIGN_JAR), "sign-app",
            "-mode", "localSign",
            "-keyAlias", key_alias,
            "-keyPwd", key_pwd,
            "-appCertFile", str(app_cert),
            "-profileFile", str(profile),
            "-inFile", str(unsigned[0]),
            "-signAlg", "SHA256withECDSA",
            "-keystoreFile", str(keystore),
            "-keystorePwd", key_pwd,
            "-outFile", str(signed),
            "-compatibleVersion", "23",
            "-signCode", "0",
        ]
        sign = subprocess.run(sign_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, shell=False, timeout=300, check=False)
        (out_dir / "sign.log").write_bytes(sign.stdout)
        if not signed.exists():
            raise TransportError(
                "签名未产出，日志尾部:\n" + sign.stdout.decode("utf-8", errors="replace")[-1500:]
            )
        # Hvigor/签名完成后，隔离工程里的私钥副本不再需要。尤其是 SDK
        # 自动生成的 P12 含有本轮临时私钥，不能跟着阶段产物长期保留；用户
        # 导入的正式 P12 也只在 CERT_DIR 原位置保留，绝不从那里删除。
        for private_copy in (project / "signing" / "debug.p12", keystore):
            try:
                private_copy.unlink(missing_ok=True)
            except OSError:
                pass
        return signed

    @staticmethod
    def _stage_offline_hvigor_dependencies(project: Path, hvigor_user_home: Path) -> None:
        """为一次 HAP 构建准备工具链自带的离线依赖。

        command-line-tools 包含 Hvigor 和 OpenHarmony 插件本体，但默认
        ``hvigorw`` 仍会先尝试联网下载 pnpm；在离线、受限网络或 Web 服务
        运行环境中，这会让一个没有第三方依赖的最小 HAP 也在构建前失败。
        这里不把任何样本协议写入工程，只复用当前工具链的构建插件，并把
        pnpm wrapper 放到本次运行自己的缓存目录。项目若声明了额外依赖，
        仍由 Hvigor 正常报告其缺失，不会伪造安装结果。
        """
        hvigor_pkg = _TOOLCHAIN_ROOT / "hvigor/hvigor"
        plugin_pkg = _TOOLCHAIN_ROOT / "hvigor/hvigor-ohos-plugin"
        if not (hvigor_pkg.is_dir() and plugin_pkg.is_dir()):
            return

        ohos_modules = project / "node_modules" / "@ohos"
        ohos_modules.mkdir(parents=True, exist_ok=True)
        for name, target in (("hvigor", hvigor_pkg), ("hvigor-ohos-plugin", plugin_pkg)):
            link = ohos_modules / name
            if link.exists() or link.is_symlink():
                continue
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError:
                # 某些受限文件系统不允许符号链接；复制工具包仍比联网失败
                # 可复现，但仅对这两个固定的工具链包做复制，不复制用户依赖。
                shutil.copytree(target, link, dirs_exist_ok=True)

        pnpm_bin = shutil.which("pnpm")
        if not pnpm_bin:
            embedded = _NODE / "lib/node_modules/corepack/shims/pnpm"
            pnpm_bin = str(embedded) if embedded.exists() else None
        if not pnpm_bin:
            return

        wrapper_tools = hvigor_user_home / "wrapper/tools"
        wrapper_bin = wrapper_tools / "node_modules/.bin"
        wrapper_bin.mkdir(parents=True, exist_ok=True)
        pnpm_pkg = wrapper_tools / "node_modules/pnpm"
        pnpm_pkg.mkdir(parents=True, exist_ok=True)
        # hvigor 只用 require.resolve 判断 wrapper 是否已准备好；实际执行
        # 仍通过 .bin/pnpm 指向当前主机已有的 pnpm，避免伪造命令输出。
        (pnpm_pkg / "package.json").write_text(
            '{"name":"pnpm","version":"10.33.2","main":"package.json"}\n',
            encoding="utf-8",
        )
        pnpm_link = wrapper_bin / "pnpm"
        if not pnpm_link.exists() and not pnpm_link.is_symlink():
            try:
                pnpm_link.symlink_to(pnpm_bin)
            except OSError:
                pnpm_link.write_text(
                    f"#!/bin/sh\nexec {shlex.quote(pnpm_bin)} \"$@\"\n",
                    encoding="utf-8",
                )
                pnpm_link.chmod(0o755)

    # ------------------------------------------------------------------
    def install_and_start(self, hap: Path) -> SendResult:
        rec = self.hdc.run(["install", "-r", str(hap)], purpose="hap:install", timeout_seconds=120)
        if rec.returncode != 0 or "successfully" not in (rec.stdout + rec.stderr).lower():
            raise TransportError(f"HAP 安装失败: {rec.stdout} {rec.stderr}")
        self._installed_bundle = BUNDLE_NAME
        self.hdc.run(
            ["shell", "aa", "force-stop", BUNDLE_NAME],
            purpose="hap:force-stop-stale",
        )
        start = self.hdc.run(
            ["shell", "aa", "start", "-b", BUNDLE_NAME, "-a", ABILITY_NAME],
            purpose="hap:start",
        )
        if start.returncode != 0:
            raise TransportError(f"aa start 失败: {start.stdout} {start.stderr}")
        return SendResult(
            reachability=INPUT_DELIVERED,
            detail=f"hap installed and started, bundle={BUNDLE_NAME}",
            transport={"kind": self.transport_id, "bundle": BUNDLE_NAME, "hap": str(hap)},
        )

    def wait_completion(
        self,
        *,
        target: str,
        seconds: float = 45.0,
        poll_interval: float = 1.0,
    ) -> tuple[bool, str]:
        """等待 HAP 明确报告发送完成，而不是按固定秒数猜测。

        ``aa start`` 只表示启动请求已受理，不表示 ``aboutToAppear`` 已经执行。
        在开发板冷启动、UI 线程繁忙或首次安装 HAP 时，实际发送可能明显晚于
        ``aa start`` 返回。旧实现固定等待 6 秒，导致 runner 在报文发出前就做
        after 快照并卸载 HAP，产生假阴性的 ``NOT_REPRODUCED``。

        HAP 模板在真正完成所有帧发送后写入
        ``HAP_POC_SENT <target>``，失败时写入 ``HAP_POC_FAIL <target>``。
        这里仅以设备侧日志作为“输入确实发出”的传输证据；漏洞效果仍由外层
        oracle 独立判断。超时不抛出“已发送”，而是返回 False，让上层生成
        ``BLOCKED_INPUT_NOT_SENT``，避免把基础设施问题伪装成安全结论。
        """
        import time

        target = str(target or "").strip()
        if not target:
            return False, "HAP 发送确认缺少 target"
        sent = f"HAP_POC_SENT {target}"
        failed = f"HAP_POC_FAIL {target}"
        deadline = time.monotonic() + max(0.0, float(seconds))
        last_text = ""
        while True:
            try:
                log = self.hdc.shell(
                    ["hilog", "-x", "-T", "VulnFounderHapPoc"],
                    purpose="hap:poc-wait",
                    timeout_seconds=15,
                )
                last_text = str(getattr(log, "stdout", "") or "")
                if sent in last_text:
                    return True, sent
                if failed in last_text:
                    # 保留 HAP 自己的失败原因，便于前端和诊断任务树区分
                    # “没有启动完成”与“启动后协议发送失败”。
                    lines = [line.strip() for line in last_text.splitlines() if target in line]
                    return False, lines[-1] if lines else failed
            except Exception as exc:  # noqa: BLE001 — 轮询失败仍应继续到超时
                last_text = f"{type(exc).__name__}: {exc}"
            if time.monotonic() >= deadline:
                return False, f"等待 {sent} 超时 {seconds:.1f}s；last={last_text[-240:]}"
            time.sleep(max(0.1, float(poll_interval)))

    def build_and_run(self, field_values: dict[str, Any], *, contract_id: str,
                      wait_seconds: float = 45.0,
                      frame_interval_seconds: float = 0.3) -> SendResult:
        """构建 → 签名 → 安装 → 启动 → 等待设备确认 HAP 已完成发送。

        ``wait_seconds`` 现在是“发送确认超时”，不是固定 sleep 时长；真正
        的漏洞效果窗口由 runner 在收到 ``HAP_POC_SENT`` 后另行计算。
        """
        # ``contract_id`` 位于契约顶层，不一定会被协议侦查器复制到
        # protocol.field_values。必须在渲染 Index.ets 之前补入 TARGET 槽位；
        # 仅在下面 wait_completion() 中设置局部 target 已经太晚，HAP 里会出现
        # ``HAP_POC_SENT  transport=...``，运行器也就无法区分本轮样本。
        rendered_values = dict(field_values)
        target = str(rendered_values.get("target") or contract_id or "").strip()
        if not target:
            raise TransportError("HAP 传输缺少 target/contract_id，拒绝构建无标识载荷")
        rendered_values["target"] = target
        build_kwargs: dict[str, Any] = {"contract_id": contract_id}
        # 默认模板本来就是 300ms，保持旧版替身/插件 build 签名兼容；只有
        # 契约明确要求其它间隔时才把新参数传入构建器。
        if abs(float(frame_interval_seconds) - 0.3) > 1e-9:
            build_kwargs["frame_interval_seconds"] = frame_interval_seconds
        hap = self.build(rendered_values, **build_kwargs)
        result = self.install_and_start(hap)

        # Index.ets 直接把 FIRST/SECOND/THIRD 作为字符串交给 socket.send。
        # 将这一刻真正写入 HAP 的线路帧保存到 transport 元数据，供运行记录和
        # Web 页面展示。这里不能只展示 contract 中的模板：模板里的
        # __RUN_PATTERN__、__MARKER_PATH__ 已经在 Runner 侧展开，用户需要看到
        # 本轮实际发送的内容以及它对应的帧顺序。
        sent_frames: list[dict[str, Any]] = []
        for index, slot in enumerate(("first", "second", "third"), start=1):
            value = rendered_values.get(slot, "")
            if value is None or str(value) == "":
                continue
            payload = str(value)
            sent_frames.append({
                "index": index,
                "slot": slot,
                "payload": payload,
                "encoding": "UTF-8",
                "byte_length": len(payload.encode("utf-8")),
                "delay_before_seconds": 0.0 if not sent_frames else float(frame_interval_seconds),
                "source": "hap_runtime_template",
            })
        result.transport["sent_frames"] = sent_frames
        result.transport["frame_count"] = len(sent_frames)
        result.transport["frame_interval_seconds"] = float(frame_interval_seconds)
        result.transport["frame_transport"] = str(rendered_values.get("mode") or "unknown")
        result.transport["frame_note"] = (
            "HAP Index.ets 使用本轮展开后的 FIRST/SECOND/THIRD 依次调用 socket.send；"
            "以下 payload 是发送给设备端点的实际 UTF-8 字符串。"
        )
        sent, detail = self.wait_completion(target=target, seconds=wait_seconds)
        result.detail = f"{result.detail}; {detail}"
        result.transport["poc_signal"] = detail
        if not sent:
            result.reachability = INPUT_NOT_SENT
        return result

    def cleanup(self) -> None:
        if not self._installed_bundle:
            return
        self.hdc.run(["shell", "aa", "force-stop", self._installed_bundle], purpose="hap:cleanup-stop")
        self.hdc.run(["uninstall", self._installed_bundle], purpose="hap:cleanup-uninstall")
        self._installed_bundle = None
