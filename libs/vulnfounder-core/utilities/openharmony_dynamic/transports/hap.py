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
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

from .base import INPUT_DELIVERED, INPUT_NOT_SENT, SendResult, ToolchainUnavailable, TransportError
from ..toolchain import build_tools_root, hap_build_toolchain_issues, toolchain_root

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
_BUILD_TOOLS_ROOT = build_tools_root()
_HVIGORW = _BUILD_TOOLS_ROOT / "hvigor/bin/hvigorw"
_NODE = _BUILD_TOOLS_ROOT / "tool/node"
_SIGN_JAR = _TOOLCHAIN_ROOT / "sdk/default/openharmony/toolchains/lib/hap-sign-tool.jar"
_HDC = _TOOLCHAIN_ROOT / "sdk/default/openharmony/toolchains/hdc"
_SDK_SIGNING_LIB = _TOOLCHAIN_ROOT / "sdk/default/openharmony/toolchains/lib"
_SDK_SIGNING_P12 = _SDK_SIGNING_LIB / "OpenHarmony.p12"
_SDK_PROFILE_DEBUG_CERT_CHAIN = _SDK_SIGNING_LIB / "OpenHarmonyProfileDebug.pem"
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


def _require_successful_process(completed: Any, stage: str) -> None:
    """Do not treat a partial output from a failed tool process as success."""

    return_code = int(getattr(completed, "returncode", 1))
    if return_code == 0:
        return
    output = getattr(completed, "stdout", b"") or getattr(completed, "stderr", b"") or ""
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    raise TransportError(
        f"{stage}失败（exit code {return_code}），日志尾部：\n{str(output)[-1800:]}"
    )



def _configure_project_skip_internal_signing(project: Path) -> None:
    """让 Hvigor 只生成 unsigned HAP，签名由后续受控步骤单独完成。"""

    profile_path = project / "build-profile.json5"
    if not profile_path.is_file():
        raise TransportError("HAP 工程缺少 build-profile.json5，无法配置 unsigned 构建")
    profile = profile_path.read_text(encoding="utf-8")
    # 只修改隔离副本。assembleApp 会因该选项跳过模块 HAP 签名；同时移除
    # 产品对 signingConfig 的引用，避免应用级 SignApp 仍要求 Hvigor 自己的
    # 加密签名材料。unsigned HAP 随后由同一工具链的 hap-sign-tool 单独签名。
    if re.search(r'(["\']?buildOption["\']?\s*:)', profile):
        raise TransportError(
            "HAP 模板已声明 buildOption；请显式合并 product.buildOption.packOptions.buildAppSkipSignHap，"
            "避免覆盖现有构建设置"
        )
    app_match = re.search(r'(?P<indent>[ \t]*)["\']?app["\']?\s*:\s*\{', profile)
    if app_match is None:
        raise TransportError("HAP 工程 build-profile.json5 缺少 app 配置对象")
    products_match = re.search(
        r'["\']?products["\']?\s*:\s*\[', profile[app_match.end():]
    )
    if products_match is None:
        raise TransportError("HAP 工程 app 配置缺少 products 数组")
    products_array_end = app_match.end() + products_match.end()
    product_open = profile.find("{", products_array_end)
    if product_open < 0:
        raise TransportError("HAP 工程 app.products 中没有产品配置对象")
    product_line_start = profile.rfind("\n", 0, product_open) + 1
    product_indent = re.match(r"[ \t]*", profile[product_line_start:product_open])
    indent = product_indent.group(0) if product_indent else ""
    inserted = (
        f'\n{indent}  "buildOption": {{\n'
        f'{indent}    "packOptions": {{ "buildAppSkipSignHap": true }}\n'
        f'{indent}  }},'
    )
    profile = profile[:product_open + 1] + inserted + profile[product_open + 1:]
    profile = re.sub(
        r'(["\']?signingConfig["\']?\s*:\s*)(?:"[^"]*"|\'[^\']*\')\s*,?',
        "",
        profile,
    )
    profile_path.write_text(profile, encoding="utf-8")


def _safe_signing_alias(prefix: str, contract_id: str) -> str:
    digest = hashlib.sha256(str(contract_id).encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"vf-{prefix}-{digest}"


def _current_device_udid(hdc: "HDCClient") -> str:
    """从当前已选中的设备读取用于 debug profile 绑定的 UDID。

    HDC serial 是连接标识，不等同于 OpenHarmony Provision Profile 中的
    UDID。profile 模板的 ``device-id-type`` 为 ``udid``，因此不能直接把
    ``hdc list targets`` 返回的 serial 写入 ``device-ids``。
    """

    try:
        record = hdc.shell(["bm", "get", "-u"], purpose="读取 HAP debug profile 所需的设备 UDID")
    except Exception as exc:  # noqa: BLE001 — 保留设备侧查询失败原因
        raise TransportError(f"无法读取当前开发板 UDID：{exc}") from exc
    if int(getattr(record, "returncode", 1)) != 0:
        detail = str(getattr(record, "stderr", "") or getattr(record, "stdout", "")).strip()
        raise TransportError("开发板 bm get -u 执行失败" + (f"：{detail[-500:]}" if detail else ""))
    output = str(getattr(record, "stdout", "") or "")
    match = re.search(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64})(?![0-9A-Fa-f])", output)
    if not match:
        raise TransportError("开发板 bm get -u 未返回有效的 64 位十六进制 UDID")
    return match.group(1).upper()


def _installed_sdk_api_version() -> int:
    """读取当前 command-line-tools 实际安装的 OpenHarmony SDK API 版本。"""

    sdk = _TOOLCHAIN_ROOT / "sdk"
    sdk_pkg = sdk / "default" / "sdk-pkg.json"
    if sdk_pkg.is_file():
        try:
            metadata = json.loads(sdk_pkg.read_text(encoding="utf-8"))
            raw_version = str(metadata.get("data", {}).get("apiVersion", "")).strip()
            if re.fullmatch(r"[1-9][0-9]*", raw_version):
                return int(raw_version)
        except (OSError, json.JSONDecodeError, AttributeError):
            pass

    versions: set[str] = set()
    for component_root in (sdk / "default" / "openharmony", sdk / "openharmony"):
        if not component_root.is_dir():
            continue
        for manifest_path in component_root.rglob("oh-uni-package.json"):
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            value = str(manifest.get("apiVersion", "")).strip()
            if re.fullmatch(r"[1-9][0-9]*", value):
                versions.add(value)
        if versions:
            break
    if len(versions) == 1:
        return int(versions.pop())
    raise TransportError(
        "无法从已安装 OpenHarmony SDK 元数据确定有效 API 版本；"
        "请检查 sdk/default/sdk-pkg.json 或组件清单"
    )


def _installed_sdk_platform_version(api_version: int) -> str:
    """读取 API 26+ 构建配置要求的点分平台版本字符串。"""

    sdk = _TOOLCHAIN_ROOT / "sdk"
    sdk_pkg = sdk / "default" / "sdk-pkg.json"
    if sdk_pkg.is_file():
        try:
            metadata = json.loads(sdk_pkg.read_text(encoding="utf-8"))
            data = metadata.get("data", {})
            if int(str(data.get("apiVersion", ""))) == api_version:
                value = str(data.get("platformVersion", "")).strip()
                if re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", value):
                    return value
        except (OSError, json.JSONDecodeError, AttributeError, TypeError, ValueError):
            pass

    versions: set[str] = set()
    for component_root in (sdk / "default" / "openharmony", sdk / "openharmony"):
        if not component_root.is_dir():
            continue
        for manifest_path in component_root.rglob("oh-uni-package.json"):
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if str(manifest.get("apiVersion", "")).strip() != str(api_version):
                continue
            value = str(manifest.get("platformVersion", "")).strip()
            if re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", value):
                versions.add(value)
        if versions:
            break
    if len(versions) == 1:
        return versions.pop()
    raise TransportError(
        f"SDK API {api_version} 缺少唯一、有效的 platformVersion 元数据"
    )


def _configure_project_compile_sdk(project: Path) -> int:
    """只在隔离 HAP 工程中将 compileSdkVersion 对齐本机 SDK。"""

    profile_path = project / "build-profile.json5"
    if not profile_path.is_file():
        return _installed_sdk_api_version()
    api_version = _installed_sdk_api_version()
    # Hvigor 6.26+ 对 API 26 改用点分版本字符串，旧 API 则要求数字。
    # 三个字段必须遵循同一 SDK schema；仅更新 compileSdkVersion 会被
    # Hvigor 的配置校验拒绝。
    sdk_value = (
        json.dumps(_installed_sdk_platform_version(api_version))
        if api_version >= 26
        else str(api_version)
    )
    profile_text = profile_path.read_text(encoding="utf-8")
    compile_pattern = r'(["\']?compileSdkVersion["\']?\s*:\s*)(?:"[^"]*"|\'[^\']*\'|\d+)'
    profile_text, compile_count = re.subn(
        compile_pattern, lambda match: match.group(1) + sdk_value, profile_text
    )
    if compile_count == 0:
        raise TransportError(
            "HAP 工程 build-profile.json5 未声明 compileSdkVersion，"
            "无法与已安装 SDK 自动匹配"
        )
    for field in ("compatibleSdkVersion", "targetSdkVersion"):
        pattern = rf'(["\']?{field}["\']?\s*:\s*)(?:"[^"]*"|\'[^\']*\'|\d+)'
        profile_text = re.sub(
            pattern, lambda match: match.group(1) + sdk_value, profile_text
        )
    profile_path.write_text(profile_text, encoding="utf-8")

    if api_version >= 26:
        # API 26 的点分版本 schema 要求新的工程模型版本。更新隔离副本中
        # 的项目级 Hvigor 配置和 package manifests；模板仓库保持不变。
        manifests = [project / "hvigor" / "hvigor-config.json5"]
        manifests.extend(sorted(project.rglob("oh-package.json5")))
        for manifest_path in dict.fromkeys(manifests):
            if not manifest_path.is_file():
                continue
            manifest_text = manifest_path.read_text(encoding="utf-8")
            manifest_text, count = re.subn(
                r'(["\']?modelVersion["\']?\s*:\s*)(?:"[^"\\]*"|\'[^\'\\]*\')',
                lambda match: match.group(1) + '"6.0.0"',
                manifest_text,
            )
            if count == 0 and manifest_path in (
                project / "hvigor" / "hvigor-config.json5",
                project / "oh-package.json5",
            ):
                raise TransportError(
                    f"{manifest_path.name} 未声明 modelVersion，无法与 API 26 SDK 匹配"
                )
            if count:
                manifest_path.write_text(manifest_text, encoding="utf-8")
    return api_version


@contextmanager
def _temporary_ascii_sdk_alias() -> Iterator[Path]:
    """为 Hvigor 提供纯 ASCII 且符合 API 版本目录约定的临时 SDK 视图。

    当前 macOS command-line-tools 对 ``local.properties`` 中的 SDK 路径做
    了字符集校验；如果项目位于非 ASCII 用户目录（例如中文路径），直接写
    工具链原路径会在 Hvigor 初始化阶段失败。另外，Command Line Tools
    将组件放在 ``sdk/default/openharmony``，而 Hvigor 按 API 版本从
    ``sdk/<apiVersion>/<component>`` 查找。这里仅在系统临时目录构造一层
    纯 ASCII 的兼容视图和组件符号链接，不复制或改写 SDK；构建完成后清理。
    """

    sdk = _TOOLCHAIN_ROOT / "sdk"
    sdk_default = sdk / "default"
    sdk_pkg = sdk_default / "sdk-pkg.json"
    if not sdk.is_dir():
        raise TransportError(f"OpenHarmony SDK 目录不存在：{sdk}")

    api_version = ""
    if sdk_pkg.is_file():
        try:
            metadata = json.loads(sdk_pkg.read_text(encoding="utf-8"))
            api_version = str(metadata.get("data", {}).get("apiVersion", "")).strip()
        except (OSError, json.JSONDecodeError, AttributeError):
            api_version = ""

    # SDK 包元数据并非所有发行形态都提供；组件清单是安全的回退来源。
    component_roots = (
        sdk / api_version if api_version else None,
        sdk_default / "openharmony",
        sdk / "openharmony",
    )
    manifests: list[tuple[Path, dict[str, Any]]] = []
    for component_root in component_roots:
        if component_root is None or not component_root.is_dir():
            continue
        for manifest_path in component_root.rglob("oh-uni-package.json"):
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            manifests.append((manifest_path, data))
        if manifests:
            break

    if not api_version:
        api_versions = {
            str(data.get("apiVersion", "")).strip()
            for _, data in manifests
            if str(data.get("apiVersion", "")).strip()
        }
        if len(api_versions) == 1:
            api_version = api_versions.pop()
    if not re.fullmatch(r"[1-9][0-9]*", api_version):
        raise TransportError(
            "无法从已安装 OpenHarmony SDK 元数据确定有效 API 版本；"
            "请检查 sdk/default/sdk-pkg.json 或组件清单"
        )
    if int(api_version) != _installed_sdk_api_version():
        raise TransportError(
            "SDK 包元数据与组件清单的 API 版本不一致，拒绝生成不确定的 Hvigor SDK 视图"
        )
    layout_version = (
        _installed_sdk_platform_version(int(api_version))
        if int(api_version) >= 26
        else api_version
    )
    if not manifests:
        raise TransportError(
            f"SDK API {api_version} 下未找到 oh-uni-package.json 组件清单"
        )

    candidates = (Path(tempfile.gettempdir()), Path("/tmp"), Path("/private/tmp"))
    temp_root = next(
        (candidate for candidate in candidates
         if candidate.is_dir() and str(candidate).isascii()),
        None,
    )
    if temp_root is None:
        raise TransportError("找不到可用的 ASCII 临时目录，无法为 Hvigor 构造 SDK 路径")

    alias_root = Path(tempfile.mkdtemp(prefix="vf-oh-sdk-", dir=str(temp_root)))
    alias = alias_root / "sdk"
    try:
        alias.mkdir()
        # 保留 SDK 包管理元数据的默认位置，Hvigor 的其他 SDK 查询仍可读取；
        # 它是目录链接，组件扫描器不会把其中的组件误认成 API 目录组件。
        if sdk_default.is_dir():
            (alias / "default").symlink_to(sdk_default, target_is_directory=True)
        api_root = alias / layout_version
        api_root.mkdir()
        for manifest_path, data in manifests:
            component_path = str(data.get("path", "")).strip()
            if not component_path or Path(component_path).is_absolute():
                continue
            normalized = Path(component_path.replace(",", os.sep))
            if any(part in ("", ".", "..") for part in normalized.parts):
                continue
            link = api_root / normalized
            link.parent.mkdir(parents=True, exist_ok=True)
            source_dir = manifest_path.parent
            if link.exists() or link.is_symlink():
                # 多个清单映射到同一目标时保留首个有效目录，避免覆盖链接。
                continue
            link.symlink_to(source_dir, target_is_directory=True)
    except OSError as exc:
        shutil.rmtree(alias_root, ignore_errors=True)
        raise TransportError(f"无法为 Hvigor 创建临时 SDK 路径：{exc}") from exc

    if not any((alias / layout_version / Path(str(data.get("path", "")).replace(",", os.sep))).is_dir()
               for _, data in manifests if str(data.get("path", "")).strip()):
        shutil.rmtree(alias_root, ignore_errors=True)
        raise TransportError(f"无法为 Hvigor 映射 SDK API {layout_version} 的组件目录")

    try:
        yield alias
    finally:
        shutil.rmtree(alias_root, ignore_errors=True)


def _generate_sdk_debug_signing_material(
    out_dir: Path,
    *,
    device_udid: str,
    contract_id: str,
) -> tuple[Path, Path, Path, str, str, str]:
    """使用 SDK 配套的 debug Profile 签名链，为当前设备生成一次性签名材料。

    debug profile 含设备 UDID，不能把某台开发板的 p7b 固定放进项目。此处
    只为本次应用生成新的 app 证书，并用设备 UDID 生成 profile 内容；Profile
    本身必须使用 SDK 配套的 ``OpenHarmonyProfileDebug.pem`` 和
    ``openharmony application profile debug`` 密钥签名，不能另造 Profile
    签名链。所有临时私钥和 profile 随契约目录清理。
    """

    udid = str(device_udid or "").strip().upper()
    if not re.fullmatch(r"[0-9A-F]{64}", udid):
        raise TransportError("无法自动生成 HAP profile：设备 UDID 必须为 64 位十六进制字符串")
    required = (_SIGN_JAR, _SDK_SIGNING_P12, _SDK_PROFILE_DEBUG_CERT_CHAIN)
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
    profile_alias = "openharmony application profile debug"
    common = ["-keystoreFile", str(keystore), "-keystorePwd", password]
    _run_sign_tool([
        "generate-keypair", "-keyAlias", app_alias, "-keyPwd", password,
        "-keyAlg", "ECC", "-keySize", "NIST-P-256", *common,
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
    app_chain = generated / "app-cert.cer"
    _run_sign_tool([
        "generate-app-cert", "-keyAlias", app_alias, "-keyPwd", password,
        "-issuer", "C=CN,O=OpenHarmony,OU=OpenHarmony Team,CN=OpenHarmony Application CA",
        "-issuerKeyAlias", "openharmony application ca", "-issuerKeyPwd", password,
        "-subject", "C=CN,O=VulnFounder,OU=Research,CN=VulnFounder App Debug",
        "-validity", "3650", "-signAlg", "SHA256withECDSA", *common,
        "-issuerKeystoreFile", str(keystore), "-issuerKeystorePwd", password,
        "-outForm", "certChain", "-rootCaCertFile", str(root_cert),
        "-subCaCertFile", str(app_ca_cert), "-outFile", str(app_chain),
    ])

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
    profile_data.setdefault("debug-info", {})["device-ids"] = [udid]
    profile_json.write_text(json.dumps(profile_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    signed_profile = generated / "debug-profile.p7b"
    _run_sign_tool([
        "sign-profile", "-mode", "localSign", "-keyAlias", profile_alias,
        "-keyPwd", password, "-profileCertFile", str(_SDK_PROFILE_DEBUG_CERT_CHAIN),
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
        toolchain_issues = hap_build_toolchain_issues(_BUILD_TOOLS_ROOT)
        if toolchain_issues:
            raise ToolchainUnavailable("HAP 构建工具链未就绪：" + "；".join(toolchain_issues))
        if not _SIGN_JAR.is_file():
            raise TransportError(f"HAP 签名工具不存在：{_SIGN_JAR}")
        if not (Path(_JAVA).is_file() or shutil.which(_JAVA)):
            raise TransportError(f"Java 运行时不存在：{_JAVA}")
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
                    device_udid=_current_device_udid(self.hdc),
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
        # 排除历史构建产物、签名物和模板自带的 node_modules。后者可能是
        # 旧工具链/不完整安装，会遮蔽本次选择的离线 Hvigor 依赖。
        shutil.copytree(_TEMPLATE_PROJECT, project,
                        ignore=shutil.ignore_patterns(
                            ".hvigor", "build", "signing", "node_modules", "*.log"
                        ))
        profile_path = project / "build-profile.json5"

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

        # Hvigor 默认把全局缓存写到 ``$HOME/.hvigor``。在 Web/批量运行中，
        # 该目录可能属于另一个用户、被系统策略设为只读，或者被多个并发
        # 构建共享，最终表现为 HAP 尚未开始编译就因 EPERM 失败。把缓存
        # 绑定到本次契约的隔离工作目录；同时用 ASCII 临时符号链接给 Hvigor
        # 暴露 SDK，避免中文项目/工具链路径被 SDK 路径校验拒绝。
        hvigor_user_home = out_dir / ".hvigor-user"
        hvigor_user_home.mkdir(parents=True, exist_ok=True)
        try:
            if profile_path.is_file():
                _configure_project_compile_sdk(project)
                _configure_project_skip_internal_signing(project)
            with _temporary_ascii_sdk_alias() as sdk_alias:
                (project / "local.properties").write_text(
                    f"sdk.dir={sdk_alias}\nnodejs.dir={_NODE}\n", encoding="utf-8"
                )
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
        except Exception:
            if _profile_name == "sdk-generated-debug":
                shutil.rmtree(out_dir / "sdk-debug-signing", ignore_errors=True)
            raise
        (out_dir / "hvigor-build.log").write_bytes(build.stdout)
        try:
            _require_successful_process(build, "Hvigor 构建")
        except TransportError:
            if _profile_name == "sdk-generated-debug":
                shutil.rmtree(out_dir / "sdk-debug-signing", ignore_errors=True)
            raise
        unsigned = sorted(project.rglob("entry-default-unsigned.hap"))
        if not unsigned:
            if _profile_name == "sdk-generated-debug":
                shutil.rmtree(out_dir / "sdk-debug-signing", ignore_errors=True)
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
            "-signCode", "1",
        ]
        sign = subprocess.run(sign_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, shell=False, timeout=300, check=False)
        (out_dir / "sign.log").write_bytes(sign.stdout)
        if sign.returncode != 0 or not signed.exists():
            if _profile_name == "sdk-generated-debug":
                shutil.rmtree(out_dir / "sdk-debug-signing", ignore_errors=True)
            raise TransportError(
                f"签名失败（exit code {sign.returncode}），日志尾部:\n"
                + sign.stdout.decode("utf-8", errors="replace")[-1500:]
            )
        # 临时生成的私钥仅用于本轮外部签名，成功后删除；用户导入的正式
        # P12 保留在 CERT_DIR 原位置，不从那里删除。
        if _profile_name == "sdk-generated-debug":
            shutil.rmtree(out_dir / "sdk-debug-signing", ignore_errors=True)
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
        hvigor_pkg = _BUILD_TOOLS_ROOT / "hvigor/hvigor"
        plugin_pkg = _BUILD_TOOLS_ROOT / "hvigor/hvigor-ohos-plugin"
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

        # Hvigor resolves its pnpm wrapper from a versioned directory.  Putting
        # it directly under ``wrapper/tools`` looks plausible but is ignored;
        # Hvigor then runs ``npm install pnpm`` and fails on offline machines.
        # Read the required version from the installed Hvigor package instead
        # of pinning a version in VulnFounder.
        pnpm_constants = hvigor_pkg / "src/common/const/path-const.js"
        try:
            constants_text = pnpm_constants.read_text(encoding="utf-8")
        except OSError:
            return
        version_match = re.search(r"PNPM_VERSION\s*=\s*['\"]([^'\"]+)['\"]", constants_text)
        if not version_match:
            return
        required_pnpm_version = version_match.group(1)

        try:
            version_result = subprocess.run(
                [pnpm_bin, "--version"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                shell=False, timeout=15, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return
        if version_result.returncode != 0:
            return
        available_pnpm_version = version_result.stdout.decode("utf-8", errors="replace").strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", available_pnpm_version):
            return

        wrapper_tools = hvigor_user_home / "wrapper/tools" / required_pnpm_version
        wrapper_bin = wrapper_tools / "node_modules/.bin"
        wrapper_bin.mkdir(parents=True, exist_ok=True)
        pnpm_pkg = wrapper_tools / "node_modules/pnpm"
        pnpm_pkg.mkdir(parents=True, exist_ok=True)
        # hvigor 只用 require.resolve 判断 wrapper 是否已准备好；实际执行
        # 仍通过 .bin/pnpm 指向当前主机已有的 pnpm，避免伪造命令输出。
        (pnpm_pkg / "package.json").write_text(
            json.dumps({
                "name": "pnpm",
                "version": available_pnpm_version,
                "main": "package.json",
            }) + "\n",
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
        install_output = rec.stdout + rec.stderr
        install_ok = rec.returncode == 0 and "successfully" in install_output.lower()
        if not install_ok and any(
            message in install_output.lower()
            for message in ("sign info inconsistent", "inconsistent signature")
        ):
            # SDK debug signing creates a fresh ephemeral app certificate per
            # build. If an earlier run left our reserved carrier bundle on the
            # board, `install -r` correctly rejects the new signer. Only remove
            # the package after verifying its bundle/vendor identity; never
            # uninstall an unrelated app in response to a generic install error.
            if self._is_vulnfounder_carrier_installed():
                removed = self.hdc.run(
                    ["uninstall", BUNDLE_NAME],
                    purpose="hap:remove-stale-carrier-signature",
                    timeout_seconds=120,
                )
                removed_output = removed.stdout + removed.stderr
                if removed.returncode == 0 and "successfully" in removed_output.lower():
                    rec = self.hdc.run(
                        ["install", str(hap)],
                        purpose="hap:install-after-signature-reset",
                        timeout_seconds=120,
                    )
                    install_output = rec.stdout + rec.stderr
                    install_ok = rec.returncode == 0 and "successfully" in install_output.lower()
                else:
                    install_output += (
                        "\n检测到旧测试包，但安全卸载失败："
                        + removed_output[-500:]
                    )
        if not install_ok:
            raise TransportError(f"HAP 安装失败: {install_output}")
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

    def _is_vulnfounder_carrier_installed(self) -> bool:
        """检查固定测试包身份，避免签名恢复时误卸载设备上的其他应用。"""

        try:
            record = self.hdc.run(
                ["shell", "bm", "dump", "-n", BUNDLE_NAME],
                purpose="hap:inspect-existing-carrier",
                timeout_seconds=30,
            )
        except Exception:  # noqa: BLE001 — 检查失败时必须按不安全处理
            return False
        if int(getattr(record, "returncode", 1)) != 0:
            return False
        output = str(getattr(record, "stdout", "") or "")
        start = output.find("{")
        if start < 0:
            return False
        try:
            # HDC may append its own channel warning after the otherwise valid
            # JSON response. Decode one JSON value and intentionally ignore
            # trailing transport diagnostics.
            bundle_info, _ = json.JSONDecoder().raw_decode(output[start:])
        except json.JSONDecodeError:
            return False
        app_info = bundle_info.get("applicationInfo")
        return (
            isinstance(bundle_info, dict)
            and bundle_info.get("bundleName") == BUNDLE_NAME
            and isinstance(app_info, dict)
            and app_info.get("vendor") == "security_research"
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
