"""有界的 source-locator 阶段编排器。

编排器把确定性阶段 worker 接到 :class:`SourceLocatorStateMachine` 上。每个
worker 只能返回一个 ``StageResult``，不能直接改变状态、执行 shell 或写仓库。
缺少 handler、返回非法下一状态或超过步数时会进入 ``NEEDS_REVIEW``，不会死循环。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .state_machine import (
    FLOW_STATES,
    LocatorSession,
    LocatorStateError,
    SourceLocatorStateMachine,
    StageResult,
    TERMINAL_STATES,
)
from .target_normalizer import TargetNormalizationError, normalize_target


class SourceLocatorOrchestratorError(ValueError):
    """Raised when an injected stage handler violates its contract."""


StageHandler = Callable[[LocatorSession], StageResult | Mapping[str, Any]]


def _coerce_result(value: StageResult | Mapping[str, Any]) -> StageResult:
    if isinstance(value, StageResult):
        return value
    if not isinstance(value, Mapping):
        raise SourceLocatorOrchestratorError("stage handler 必须返回 StageResult 或 JSON 对象")
    try:
        return StageResult(
            next_state=value["next_state"],
            summary_zh=value["summary_zh"],
            updates=value.get("updates", {}),
            event_type=value.get("event_type", "state.changed"),
            evidence_ids=tuple(value.get("evidence_ids", ())),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SourceLocatorOrchestratorError("stage handler 返回字段不完整") from exc


def normalize_stage(session: LocatorSession) -> StageResult:
    """默认的第一阶段：只做确定性 TargetSpec 标准化。"""

    try:
        target = normalize_target(session.raw_target, target_revision=session.target_revision)
    except TargetNormalizationError as exc:
        return StageResult(
            next_state="NEEDS_REVIEW",
            summary_zh="目标描述无法安全标准化，等待人工修正",
            updates={"last_error": str(exc)},
            event_type="normalize.failed",
        )
    return StageResult(
        next_state="PROBE_OPENGROK",
        summary_zh="已将用户描述标准化为受限目标规格",
        updates={"target": target.to_dict()},
        event_type="target.normalized",
    )


@dataclass
class SourceLocatorOrchestrator:
    """Run a bounded sequence of injected stages until pause or terminal state."""

    machine: SourceLocatorStateMachine
    handlers: Mapping[str, StageHandler]
    max_steps: int = 32

    def __post_init__(self) -> None:
        if not isinstance(self.machine, SourceLocatorStateMachine):
            raise SourceLocatorOrchestratorError("machine 类型无效")
        if not isinstance(self.handlers, Mapping):
            raise SourceLocatorOrchestratorError("handlers 必须是映射")
        if isinstance(self.max_steps, bool) or not isinstance(self.max_steps, int) or not 1 <= self.max_steps <= 128:
            raise SourceLocatorOrchestratorError("max_steps 必须是 1 到 128 的整数")
        for state, handler in self.handlers.items():
            if state not in FLOW_STATES:
                raise SourceLocatorOrchestratorError(f"handler state 无效：{state}")
            if not callable(handler):
                raise SourceLocatorOrchestratorError(f"handler {state} 不可调用")

    @classmethod
    def with_normalizer(
        cls,
        machine: SourceLocatorStateMachine,
        handlers: Mapping[str, StageHandler] | None = None,
        *,
        max_steps: int = 32,
    ) -> "SourceLocatorOrchestrator":
        stage_handlers = dict(handlers or {})
        stage_handlers.setdefault(
            "INTAKE",
            lambda session: StageResult(
                next_state="NORMALIZE_TARGET",
                summary_zh="已进入目标标准化阶段",
                event_type="state.changed",
            ),
        )
        stage_handlers.setdefault("NORMALIZE_TARGET", normalize_stage)
        return cls(machine, stage_handlers, max_steps=max_steps)

    def _needs_review(self, reason: str) -> LocatorSession:
        if self.machine.session.state in TERMINAL_STATES:
            return self.machine.session
        try:
            return self.machine.fail(reason, state="NEEDS_REVIEW")
        except LocatorStateError as exc:
            raise SourceLocatorOrchestratorError(str(exc)) from exc

    def run(self, *, max_steps: int | None = None) -> LocatorSession:
        limit = self.max_steps if max_steps is None else max_steps
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= self.max_steps:
            raise SourceLocatorOrchestratorError("本次运行步数超过 planner 上限")
        steps = 0
        while self.machine.session.state not in TERMINAL_STATES and self.machine.session.state != "AWAIT_USER_CONFIRMATION":
            if steps >= limit:
                return self._needs_review("单次编排步数达到上限，防止状态机死循环")
            current = self.machine.session.state
            handler = self.handlers.get(current)
            if handler is None:
                return self._needs_review(f"状态 {current} 没有注册确定性 handler")
            try:
                result = _coerce_result(handler(self.machine.session))
                if result.next_state == current:
                    return self._needs_review(f"状态 {current} 的 handler 未推进状态")
                self.machine.transition(
                    result.next_state,
                    summary_zh=result.summary_zh,
                    event_type=result.event_type,
                    updates=result.updates,
                    evidence_ids=result.evidence_ids,
                )
            except (LocatorStateError, SourceLocatorOrchestratorError) as exc:
                return self._needs_review(str(exc))
            except Exception as exc:  # handler adapter boundary
                return self._needs_review("阶段 handler 异常：" + " ".join(str(exc).split())[:256])
            steps += 1
        return self.machine.session

    resume = run

    def confirm(self, *, confirmation_id: str | None = None) -> LocatorSession:
        return self.machine.confirm(confirmation_id=confirmation_id)

    def reject(self, reason: str, **constraints: Any) -> LocatorSession:
        return self.machine.reject(reason, **constraints)

    def apply_feedback(self) -> LocatorSession:
        return self.machine.resume_after_feedback()

    def cancel(self, *, reason: str = "用户取消定位") -> LocatorSession:
        return self.machine.cancel(reason=reason)


__all__ = [
    "SourceLocatorOrchestrator",
    "SourceLocatorOrchestratorError",
    "StageHandler",
    "normalize_stage",
]
