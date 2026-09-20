"""HAP 传输层 v2（§9.1 / R8）。

模板参数化：Index.ets 模板占位符 ← 契约 protocol.field_values + entry.endpoint。
构建 → 签名 → 安装 → 启动 → （观测由外层负责）→ force-stop → 卸载。
bundle 名固定为签名 profile 允许的 com.security.research.trigger。
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import INPUT_DELIVERED, INPUT_NOT_SENT, SendResult, TransportError

if TYPE_CHECKING:
    from ..hdc_client import HDCClient

_SUITE_DIR = (
    Path(__file__).resolve().parents[5] / "evaluation_dataset" / "vulnerability" / "result" / "hap_poc_suite"
)
_TEMPLATE_PROJECT = _SUITE_DIR / "dp01_hap"
_TEMPLATE_INDEX = _SUITE_DIR / "HAP_INDEX.ets.in"

_TOOLCHAIN_ROOT = (
    Path(__file__).resolve().parents[2] / "dynamic_tester" / "toolchains" /
    "commandline-tools-mac-arm64-6.1.0.860" / "command-line-tools"
)
_HVIGORW = _TOOLCHAIN_ROOT / "hvigor/bin/hvigorw"
_NODE = _TOOLCHAIN_ROOT / "tool/node"
_SIGN_JAR = _TOOLCHAIN_ROOT / "sdk/default/openharmony/toolchains/lib/hap-sign-tool.jar"
_HDC = _TOOLCHAIN_ROOT / "sdk/default/openharmony/toolchains/hdc"

CERT_DIR = Path("/Users/shiyu/学习/hyl_project/harmony_exploit/tools/hap_cert")
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
    ) -> Path:
        """模板参数化 → hvigor 构建 → hap-sign-tool 签名，返回 signed.hap 路径。"""
        for required in ("mode", "host", "port"):
            if required not in field_values:
                raise TransportError(f"HAP 传输缺少 field_values[{required!r}]")
        if not _TEMPLATE_PROJECT.exists() or not _TEMPLATE_INDEX.exists():
            raise TransportError(f"HAP 模板缺失: {_TEMPLATE_PROJECT}")
        out_dir = self.work_root / f"vf-hap-{contract_id}"
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)
        project = out_dir / "project"
        # 排除历史构建产物（build*.log / build 目录）与签名物，但保留 build-profile.json5
        shutil.copytree(_TEMPLATE_PROJECT, project,
                        ignore=shutil.ignore_patterns(".hvigor", "build", "signing", "*.log"))

        index_src = _TEMPLATE_INDEX.read_text(encoding="utf-8")
        for placeholder, key in _PLACEHOLDER_MAP.items():
            value = str(field_values.get(key, ""))
            index_src = index_src.replace(placeholder, value)
        index_path = project / "Entry/src/main/ets/pages/Index.ets"
        index_path.write_text(index_src, encoding="utf-8")

        (project / "local.properties").write_text(
            f"sdk.dir={_TOOLCHAIN_ROOT / 'sdk'}\nnodejs.dir={_NODE}\n", encoding="utf-8"
        )

        env = {
            **dict(__import__("os").environ),
            "NODE_HOME": str(_NODE),
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
            "java", "-jar", str(_SIGN_JAR), "sign-app",
            "-mode", "localSign",
            "-keyAlias", KEY_ALIAS,
            "-keyPwd", KEY_PWD,
            "-appCertFile", str(CERT_DIR / "oh_release_chain.cer"),
            "-profileFile", str(CERT_DIR / "oh_profile8.p7b"),
            "-inFile", str(unsigned[0]),
            "-signAlg", "SHA256withECDSA",
            "-keystoreFile", str(CERT_DIR / "oh_release.p12"),
            "-keystorePwd", KEY_PWD,
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
        return signed

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

    def wait_completion(self, seconds: float = 6.0) -> None:
        """给 HAP 侧异步发送留时间窗（Index.aboutToAppear → runPoc）。"""
        import time

        time.sleep(seconds)

    def build_and_run(self, field_values: dict[str, Any], *, contract_id: str,
                      wait_seconds: float = 6.0) -> SendResult:
        """构建 → 签名 → 安装 → 启动 → 等待 HAP 侧异步发送完成。"""
        hap = self.build(field_values, contract_id=contract_id)
        result = self.install_and_start(hap)
        self.wait_completion(wait_seconds)
        return result

    def cleanup(self) -> None:
        if not self._installed_bundle:
            return
        self.hdc.run(["shell", "aa", "force-stop", self._installed_bundle], purpose="hap:cleanup-stop")
        self.hdc.run(["uninstall", self._installed_bundle], purpose="hap:cleanup-uninstall")
        self._installed_bundle = None
