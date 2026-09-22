"""契约驱动的 CLI / 事件总线设备载体。

CLI 和事件发布不是同一种业务协议，但二者都可以由“设备侧可执行文件 +
参数数组”表达。这里刻意不接受 shell 字符串：协议 Agent 只能提交 argv
列表，运行器通过 HDC 的参数数组执行，并把实际命令、回执和返回码写入
``SendResult``。这样既支持未知的 OpenHarmony 服务，也不会为了支持一个
样本把命令硬编码进运行器。
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from ..models import ProtocolSpec
from .base import INPUT_DELIVERED, INPUT_NOT_SENT, INPUT_REJECTED, SendResult

if TYPE_CHECKING:
    from ..hdc_client import HDCClient


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SHELL_META_RE = re.compile(r"[;|&>$`\n\r]")
_SHELL_NAMES = {"sh", "bash", "ash", "busybox", "shell"}


def validate_command_argv(value: Any) -> list[str]:
    """校验并复制设备命令 argv。

    返回空列表表示不合法；调用者可以把更具体的原因交给 validator。禁止
    ``sh -c``/shell 字符串，避免模型把设备命令退化成任意 shell 执行。
    参数本身仍允许空格、冒号和路径等普通 CLI 内容；危险控制字符和 shell
    控制运算符必须通过明确的协议编码器表达，而不能出现在命令数组里。
    """
    if not isinstance(value, list) or not value or any(not isinstance(item, str) for item in value):
        return []
    argv = [str(item) for item in value]
    if any(not item or _CONTROL_RE.search(item) or _SHELL_META_RE.search(item) for item in argv):
        return []
    command_name = argv[0].rsplit("/", 1)[-1].lower()
    if command_name in _SHELL_NAMES:
        return []
    if command_name in _SHELL_NAMES or (len(argv) >= 2 and argv[1] == "-c"):
        return []
    return argv


def command_argv_for(protocol: ProtocolSpec, kind: str) -> tuple[list[str], str]:
    """从契约参数空间读取当前载体的命令数组。

    ``command_argv`` 是统一后备键；CLI/event_bus 各自的专用键优先。支持
    ``field_values`` 是为了兼容早期草案，但新产物应把载体命令放在
    ``protocol.param_space``，避免把设备命令误当成线路业务字段。
    """
    space = getattr(protocol, "param_space", None) or {}
    fields = protocol.field_values or {}
    keys = (
        ("cli_argv", "command_argv", "publish_argv")
        if kind == "cli" else
        ("event_argv", "publish_argv", "command_argv")
    )
    for key in keys:
        for source in (space, fields):
            if key in source:
                value = source.get(key)
                return (list(value), key) if isinstance(value, list) else ([], key)
    return [], ""


class DeviceCommandTransport:
    """CLI/event_bus 共用的安全设备命令载体。"""

    def __init__(self, hdc: "HDCClient", *, kind: str) -> None:
        if kind not in {"cli", "event_bus"}:
            raise ValueError(f"不支持的命令载体类型: {kind}")
        self.hdc = hdc
        self.kind = kind
        self.transport_id = kind

    def send(
        self,
        protocol: ProtocolSpec,
        descriptor=None,
        *,
        purpose: str = "",
    ) -> SendResult:
        argv, source_key = command_argv_for(protocol, self.kind)
        valid = validate_command_argv(argv)
        meta: dict[str, Any] = {
            "kind": self.kind,
            "argv": list(argv),
            "argv_source": source_key,
            "shell": False,
            "descriptor_id": getattr(descriptor, "descriptor_id", ""),
        }
        if not valid:
            return SendResult(
                reachability=INPUT_NOT_SENT,
                detail=(f"{self.kind} 载体缺少合法 argv 数组（需要 param_space.{source_key or 'command_argv'}，"
                        "且禁止 shell 字符串）"),
                transport=meta,
            )
        try:
            record = self.hdc.shell(valid, purpose=purpose or f"{self.kind}:send")
        except Exception as exc:  # noqa: BLE001 — HDC/设备基础设施失败
            meta["error"] = f"{type(exc).__name__}: {exc}"
            return SendResult(
                reachability=INPUT_NOT_SENT,
                detail=f"设备命令未执行：{type(exc).__name__}: {exc}",
                transport=meta,
            )
        stdout = str(record.stdout or "")
        stderr = str(record.stderr or "")
        meta.update({
            "returncode": int(record.returncode),
            "stdout": stdout[-4096:],
            "stderr": stderr[-4096:],
            "command_record": record.to_dict(),
        })
        if record.returncode == 0:
            return SendResult(
                reachability=INPUT_DELIVERED,
                detail=f"{self.kind} 设备命令已执行",
                response_excerpt=(stdout or stderr)[-4096:],
                transport=meta,
            )
        return SendResult(
            reachability=INPUT_REJECTED,
            detail=f"{self.kind} 设备命令返回 rc={record.returncode}",
            response_excerpt=(stdout or stderr)[-4096:],
            transport=meta,
        )

