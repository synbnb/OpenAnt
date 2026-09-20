"""传输层基类（§9.1）。

传输层职责：把编码后的 payload 送达设备侧入口，并回报送达结果。
它不观测效果（观测归 observation 层），不判定（判定归 verdict 层）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..hdc_client import HDCClient

# reachability 取值（§12.1），verdict 层消费
INPUT_DELIVERED = "INPUT_DELIVERED"
INPUT_REJECTED = "INPUT_REJECTED"
INPUT_NOT_SENT = "INPUT_NOT_SENT"


@dataclass
class SendResult:
    reachability: str                      # INPUT_DELIVERED / INPUT_REJECTED / INPUT_NOT_SENT
    detail: str = ""
    syscalls: list[dict[str, Any]] = field(default_factory=list)   # native client 的逐系统调用记录
    response_excerpt: str = ""
    transport: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reachability": self.reachability,
            "detail": self.detail,
            "syscalls": list(self.syscalls),
            "response_excerpt": self.response_excerpt,
            "transport": dict(self.transport),
        }


class TransportError(RuntimeError):
    """传输层基础设施错误（构建失败、推送失败等）。区别于 INPUT_REJECTED。"""
