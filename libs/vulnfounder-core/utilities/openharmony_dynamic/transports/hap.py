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
        project = out_dir / "project"
        # 排除历史构建产物（build*.log / build 目录）与签名物，但保留 build-profile.json5
        shutil.copytree(_TEMPLATE_PROJECT, project,
                        ignore=shutil.ignore_patterns(".hvigor", "build", "signing", "*.log"))

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
