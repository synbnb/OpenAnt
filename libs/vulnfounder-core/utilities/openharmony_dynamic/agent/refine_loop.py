"""试跑-修正闭环（自动化方案 §5）——动态测试自动化的核心。

Runner.run（现有，语义不变）→ 确定性终态分类 → 观测证据包（diagnosis）
→ LLM 修订契约 → 重新硬校验 → 再跑；预算门内循环直到诚实终态。

LLM 只有修订权；执行与判定永远由确定性代码完成。修订只能改动
field_values / param_space / oracle 路径与载体 / hilog_expectations /
fault 描述 / cleanup；禁止改动 entry.kind、descriptor_id、identity、risk。
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..contracts.registry import contract_from_dict
from ..models import Contract
from ..protocols import get_descriptor
from ..runner import Runner
from .budget import Budget
from .diagnosis import build_diagnosis

# LLM 基础设施延迟导入（需 .venv/bin/python + sys.path 前置）；
# LLM 不可用时闭环退化为"只跑不修"（诚实返回首跑结果）。
_llm_available: bool | None = None


def _llm_binding():
    global _llm_available
    if _llm_available is False:
        return None
    try:
        root = Path(__file__).resolve().parents[3]
        core = str(root / "libs" / "vulnfounder-core")
        if core not in sys.path:
            sys.path.insert(0, core)
        from utilities.llm.helpers import simple_text  # noqa: PLC0415
        from utilities.llm.registry import (  # noqa: PLC0415
            build_phase_registry,
            load_config_file,
            resolve_llm_config,
        )

        cf = load_config_file()
        lc = resolve_llm_config(cf, None)
        registry = build_phase_registry(cf, lc)
        # 阶段名必须用 llm/config.py PHASES 封闭集内的 canonical 名
        binding = registry.get("dynamic_test")
        _llm_available = True
        return binding, simple_text
    except Exception:  # noqa: BLE001 — LLM 基础设施不可用 → 退化模式
        _llm_available = False
        return None


_REVISE_SYSTEM_PROMPT = (
    "你是 OpenHarmony 真机动态测试的契约修订器。输入是一份失败的测试运行"
    "的结构化诊断证据（状态、逐系统调用、预言机细节、guard 拒绝行、hilog 摘录）。\n"
    "任务：修订契约 JSON，使下一次运行能真实触发目标漏洞。\n"
    "硬规则：\n"
    "1. 只输出一个 JSON 对象（修订后的完整契约），不要任何解释文字。\n"
    "2. 只允许改动 protocol.field_values、protocol.param_space、"
    "oracle.artifact_forms（path/content_contains/output_surface）、"
    "oracle.hilog_expectations、fault.description、cleanup.remote_paths。\n"
    "3. 禁止改动 contract_id、entry、identity、risk、protocol.descriptor_id、"
    "protocol.frame_sequence。\n"
    "4. 保持 run 唯一性：预埋/观测路径必须包含 __RUN_DIR__ 或 __SRC_FILE__ 等"
    "占位符，不得写死固定路径。\n"
    "5. 修订必须基于证据：例如 hilog 显示 Token mismatch 时检查发送侧变换；"
    "目录不存在时把产物移到 __RUN_DIR__ 下。\n"
    "6. 若诊断显示问题超出可修订范围，输出 {\"unfixable\": \"<原因>\"}。"
)


@dataclass
class RefineOutcome:
    """闭环的诚实终态。"""

    contract_id: str
    status: str                       # CONFIRMED / NOT_REPRODUCED / UNPROVEN_INPUT_INFLUENCE / BLOCKED_* / INCONCLUSIVE / INFRA_ERROR / REQUIRES_*
    terminal: bool
    run_id: str = ""
    evidence_grade: str = ""
    stopped_reason: str = ""          # "" | budget_exhausted | unfixable | llm_unavailable | infra_retry_exhausted
    rounds: int = 0                   # 实际执行的 runner 轮数
    revisions: int = 0
    final_status: str = ""            # 最后一轮 runner 的 status（与 status 可能不同：预算截断时）
    error: str = ""
    budget: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "status": self.status,
            "terminal": self.terminal,
            "run_id": self.run_id,
            "evidence_grade": self.evidence_grade,
            "stopped_reason": self.stopped_reason,
            "rounds": self.rounds,
            "revisions": self.revisions,
            "final_status": self.final_status,
            "error": self.error,
            "budget": dict(self.budget),
        }


def classify(rec: Any) -> tuple[bool, str]:
    """确定性终态分类（方案 §5.2）。返回 (是否终态, 终态理由)。"""
    verdict = rec.verdict or {}
    status = verdict.get("status", "")
    # runner 早期阶段异常 → rec.state=INFRA_ERROR（verdict 未产出）
    if not status and getattr(rec, "state", "") == "INFRA_ERROR":
        return False, "infra_error"
    if status == "CONFIRMED":
        return True, "confirmed"
    if status == "NOT_REPRODUCED":
        return True, "effect_absent"
    if status.startswith("REQUIRES_"):
        return True, "compile_gate"
    if status == "UNPROVEN_INPUT_INFLUENCE":
        # 交给上层：有 guard 拒绝证据时可修订一次，否则终态
        return False, "unproven_influence"
    if status == "INFRA_ERROR":
        return False, "infra_error"
    # BLOCKED_* / INCONCLUSIVE：典型可修订对象
    return False, "revision_candidate"


# 可修订字段白名单（方案 §5.5）
_REVISIBLE_TOP_BLOCKS = {"protocol", "oracle", "fault", "cleanup"}


def _restrict_revision(original: dict[str, Any], revised: dict[str, Any]) -> dict[str, Any]:
    """把 LLM 修订稿限制到可修订块；其余块强制回退原值。"""
    merged = json.loads(json.dumps(original))  # 深拷贝
    for block in _REVISIBLE_TOP_BLOCKS:
        if block in revised:
            merged[block] = revised[block]
    return merged


def revise_contract(contract: Contract, diagnosis_prompt: str) -> tuple[Contract | None, str]:
    """LLM 修订契约。返回 (新契约 or None, 说明)。

    LLM 不可用 / 输出不合法 / 声明 unfixable → (None, 原因)。
    """
    llm = _llm_binding()
    if llm is None:
        return None, "llm_unavailable"
    binding, simple_text = llm
    prompt = (
        "当前契约 JSON：\n"
        + json.dumps(contract.to_dict(), ensure_ascii=False, indent=2)
        + "\n\n失败运行的诊断证据：\n"
        + diagnosis_prompt
        + "\n\n请输出修订后的完整契约 JSON。"
    )
    text = simple_text(binding, prompt, system=_REVISE_SYSTEM_PROMPT, max_tokens=8000)
    text = text.strip()
    # 剥掉可能的 ```json 围栏
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    try:
        revised_raw = json.loads(text.strip())
    except json.JSONDecodeError as exc:
        return None, f"llm_output_invalid_json: {exc}"
    if not isinstance(revised_raw, dict):
        return None, "llm_output_not_object"
    if "unfixable" in revised_raw:
        return None, f"unfixable: {revised_raw['unfixable']}"
    original_raw = contract.to_dict()
    merged = _restrict_revision(original_raw, revised_raw)
    try:
        return contract_from_dict(merged), "revised"
    except Exception as exc:  # noqa: BLE001 — 修订稿结构非法
        return None, f"revised_contract_invalid: {exc}"


def refine_loop(
    hdc,
    contract: Contract,
    *,
    budget: Budget | None = None,
    max_infra_retries: int = 1,
    runner_factory: Callable[[Any], Runner] | None = None,
) -> RefineOutcome:
    """试跑-修正闭环主入口（方案 §5.1）。

    contract 可来自契约编译器（全自动路径）或手写固件（回归锚定模式）。
    """
    budget = budget or Budget()
    runner = (runner_factory or (lambda h: Runner(hdc)))(hdc)
    outcome = RefineOutcome(contract_id=contract.contract_id, status="", terminal=False)
    revision_history: list[str] = []
    infra_retries = 0
    last_error = ""

    while True:
        if not budget.can_send():
            outcome.status = outcome.final_status or "BUDGET_EXHAUSTED"
            outcome.terminal = True
            outcome.stopped_reason = "budget_exhausted"
            break
        budget.count_send()

        rec = runner.run(contract)
        outcome.rounds += 1
        outcome.run_id = rec.run_id
        outcome.final_status = (rec.verdict or {}).get("status", "") or rec.state
        outcome.evidence_grade = (rec.verdict or {}).get("evidence_grade", "")

        terminal, reason = classify(rec)
        if terminal:
            outcome.status = outcome.final_status
            outcome.terminal = True
            outcome.stopped_reason = reason
            break

        # INFRA_ERROR：预算外原样重跑一次
        if reason == "infra_error":
            last_error = rec.error
            if infra_retries < max_infra_retries:
                infra_retries += 1
                outcome.revisions += 0  # 原样重跑不计修订
                continue
            outcome.status = "INFRA_ERROR"
            outcome.terminal = True
            outcome.stopped_reason = "infra_retry_exhausted"
            outcome.error = last_error
            break

        if not budget.can_revise():
            outcome.status = outcome.final_status or "UNFINISHED"
            outcome.terminal = True
            outcome.stopped_reason = "budget_exhausted"
            break

        # 组装诊断 → LLM 修订
        try:
            descriptor = get_descriptor(contract.protocol.descriptor_id)
        except KeyError:
            descriptor = None
        diag = build_diagnosis(
            rec.to_dict(), descriptor=descriptor, revision_history=revision_history
        )
        new_contract, note = revise_contract(contract, diag.to_prompt())
        if new_contract is None:
            if note.startswith("unfixable"):
                outcome.status = outcome.final_status or "UNFINISHED"
                outcome.terminal = True
                outcome.stopped_reason = note
            elif note == "llm_unavailable":
                outcome.status = outcome.final_status or "UNFINISHED"
                outcome.terminal = True
                outcome.stopped_reason = "llm_unavailable"
            else:
                # LLM 输出不合法：计一次校验失败；连续超限 → 诚实降级
                budget.count_validation_failure([note])
                if budget.validation_spent():
                    outcome.status = outcome.final_status or "UNFINISHED"
                    outcome.terminal = True
                    outcome.stopped_reason = f"revision_validation_spent: {note}"
                    break
                continue
            break

        budget.count_revision()
        budget.reset_validation_failures()
        revision_history.append(f"round{outcome.rounds}: {note}")
        outcome.revisions += 1
        contract = new_contract

    outcome.budget = budget.to_dict()
    return outcome
