"""预算门（自动化方案 §5.4）：修订轮数 / 真实发送 / 设备命令 / 墙钟。

所有 LLM 修订循环与真实设备发送都受预算约束；预算耗尽时当前结果
原样作为终态返回（stopped_reason=budget_exhausted），绝不降低标准。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Budget:
    max_revisions: int = 3              # LLM 修订轮数上限
    max_real_sends: int = 6             # 真实设备发送次数上限（含首轮）
    max_device_commands: int = 600      # 单 finding 设备命令上限（hdc 台账计数）
    max_wall_seconds: int = 1800        # 单 finding 墙钟上限
    validation_failures_limit: int = 2  # 连续校验失败 → 诚实降级（防 LLM 打转）

    revisions_used: int = 0
    real_sends_used: int = 0
    consecutive_validation_failures: int = 0
    started_at: float = field(default_factory=time.time)
    events: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------
    def can_revise(self) -> bool:
        """是否还允许一次（修订 + 重跑）循环。"""
        return (
            self.revisions_used < self.max_revisions
            and self.real_sends_used < self.max_real_sends
            and not self.wall_exhausted()
        )

    def can_send(self) -> bool:
        return self.real_sends_used < self.max_real_sends and not self.wall_exhausted()

    def wall_exhausted(self) -> bool:
        return (time.time() - self.started_at) >= self.max_wall_seconds

    # ------------------------------------------------------------------
    def count_revision(self) -> None:
        self.revisions_used += 1
        self._log("revision", used=self.revisions_used, limit=self.max_revisions)

    def count_send(self) -> None:
        self.real_sends_used += 1
        self._log("send", used=self.real_sends_used, limit=self.max_real_sends)

    def count_validation_failure(self, errors: list[str]) -> None:
        self.consecutive_validation_failures += 1
        self._log("validation_failure", count=self.consecutive_validation_failures,
                  errors=errors)

    def reset_validation_failures(self) -> None:
        self.consecutive_validation_failures = 0

    def validation_spent(self) -> bool:
        return self.consecutive_validation_failures >= self.validation_failures_limit

    def exhausted_reasons(self) -> list[str]:
        """当前已耗尽的预算维度（用于诚实终态标注）。"""
        reasons: list[str] = []
        if self.revisions_used >= self.max_revisions:
            reasons.append("revisions")
        if self.real_sends_used >= self.max_real_sends:
            reasons.append("real_sends")
        if self.wall_exhausted():
            reasons.append("wall_clock")
        return reasons

    def remaining_sends(self) -> int:
        return max(0, self.max_real_sends - self.real_sends_used)

    def _log(self, kind: str, **payload: Any) -> None:
        self.events.append({"kind": kind, "t": time.time(), **payload})

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_revisions": self.max_revisions,
            "max_real_sends": self.max_real_sends,
            "max_device_commands": self.max_device_commands,
            "max_wall_seconds": self.max_wall_seconds,
            "revisions_used": self.revisions_used,
            "real_sends_used": self.real_sends_used,
            "consecutive_validation_failures": self.consecutive_validation_failures,
            "wall_elapsed": round(time.time() - self.started_at, 1),
            "events": list(self.events),
        }
