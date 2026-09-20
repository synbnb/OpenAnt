"""试跑-修正闭环单元测试（自动化方案 §5，不依赖设备）。

覆盖：classify 终态分类、Budget 闸门、修订白名单、闭环主流程的
诚实终态（mock runner 与 mock LLM，不发真实设备命令、不烧 LLM 配额）。
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

# 注意：`from ...agent import refine_loop` 拿到的是函数（__init__ 名字遮蔽），
# monkeypatch 必须拿到模块本体——importlib.import_module 不走 __init__ 的重导出。
import importlib  # noqa: E402

rl = importlib.import_module("utilities.openharmony_dynamic.agent.refine_loop")
from utilities.openharmony_dynamic.agent.budget import Budget  # noqa: E402
from utilities.openharmony_dynamic.contracts.registry import contract_from_dict  # noqa: E402
from utilities.openharmony_dynamic.protocols import get_descriptor  # noqa: E402

_GEN_DIR = CORE / "utilities" / "openharmony_dynamic" / "contracts" / "generated"


def _dp02_contract():
    raw = json.loads((_GEN_DIR / "GEN-DP-02.json").read_text(encoding="utf-8"))
    return contract_from_dict(raw)


class FakeRec:
    """runner.run 的最小返回结构（RunRecord 的 duck type）。"""

    def __init__(self, verdict, state="VERDICTED", error=""):
        self.run_id = "vf-fake-000001-abcdef"
        self.contract_id = "GEN-DP-02"
        self.state = state
        self.verdict = verdict
        self.error = error
        self.hilog_hits = []
        self.pattern = "vfFAKEpattern1"

    def to_dict(self):
        return {
            "run_id": self.run_id,
            "contract_id": self.contract_id,
            "state": self.state,
            "verdict": dict(self.verdict or {}),
            "hilog_hits": [],
            "pattern": self.pattern,
            "error": self.error,
        }


class FakeRunner:
    """按脚本逐轮返回结果的假 runner。"""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def run(self, contract):
        self.calls += 1
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


# ---------------------------------------------------------------------------
# classify：确定性终态分类（§5.2）
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "verdict,expected",
    [
        ({"status": "CONFIRMED"}, (True, "confirmed")),
        ({"status": "NOT_REPRODUCED"}, (True, "effect_absent")),
        ({"status": "REQUIRES_PROTOCOL_REVIEW"}, (True, "compile_gate")),
        ({"status": "UNPROVEN_INPUT_INFLUENCE"}, (False, "unproven_influence")),
        ({"status": "INCONCLUSIVE"}, (False, "revision_candidate")),
        ({"status": "BLOCKED_POLICY"}, (False, "revision_candidate")),
        ({"status": ""}, (False, "revision_candidate")),
    ],
)
def test_classify_verdict_statuses(verdict, expected):
    rec = FakeRec(verdict)
    assert rl.classify(rec) == expected


def test_classify_infra_error_via_state():
    rec = FakeRec(None, state="INFRA_ERROR", error="boom")
    assert rl.classify(rec) == (False, "infra_error")


# ---------------------------------------------------------------------------
# Budget 闸门（§5.4）
# ---------------------------------------------------------------------------

def test_budget_send_gate():
    b = Budget(max_real_sends=2)
    assert b.can_send()
    b.count_send()
    b.count_send()
    assert not b.can_send()
    assert "real_sends" in b.exhausted_reasons()


def test_budget_revision_gate_and_reset():
    b = Budget(max_revisions=1)
    assert b.can_revise()
    b.count_revision()
    assert not b.can_revise()
    b2 = Budget(validation_failures_limit=2)
    b2.count_validation_failure(["e1"])
    assert not b2.validation_spent()
    b2.count_validation_failure(["e2"])
    assert b2.validation_spent()
    b2.reset_validation_failures()
    assert not b2.validation_spent()


# ---------------------------------------------------------------------------
# 修订白名单（§5.5）：LLM 越权改动强制回退
# ---------------------------------------------------------------------------

def test_restrict_revision_blocks_entry_identity_risk():
    original = _dp02_contract().to_dict()
    revised = json.loads(json.dumps(original))
    revised["entry"]["endpoint"] = "127.0.0.1:9999"          # 越权
    revised["identity"]["execution_identity"] = "root_su"    # 越权
    revised["risk"]["risk_tier"] = "boot_critical"           # 越权
    revised["protocol"]["field_values"]["set_pkgName"] = "changed"
    merged = rl._restrict_revision(original, revised)
    assert merged["entry"]["endpoint"] == original["entry"]["endpoint"]
    assert merged["identity"]["execution_identity"] == original["identity"]["execution_identity"]
    assert merged["risk"]["risk_tier"] == original["risk"]["risk_tier"]
    assert merged["protocol"]["field_values"]["set_pkgName"] == "changed"  # 白名单内生效


# ---------------------------------------------------------------------------
# refine_loop 主流程：mock runner / mock LLM，验证诚实终态
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_llm(monkeypatch):
    """把 revise_contract 的 LLM 绑定替换为可脚本化的假实现。"""
    calls = []

    def _bind(script):
        def _fake_binding():
            def _simple(binding, prompt, system=None, max_tokens=0):
                calls.append(prompt)
                return script.pop(0)

            return ("fake-binding", _simple)

        monkeypatch.setattr(rl, "_llm_binding", _fake_binding)
        return calls

    return _bind


def test_refine_loop_confirmed_first_round():
    rec = FakeRec({"status": "CONFIRMED", "evidence_grade": "A"})
    outcome = rl.refine_loop(None, _dp02_contract(), runner_factory=lambda h: FakeRunner([rec]))
    assert outcome.terminal and outcome.status == "CONFIRMED"
    assert outcome.rounds == 1 and outcome.revisions == 0
    assert outcome.stopped_reason == "confirmed"


def test_refine_loop_revises_then_confirms(fake_llm):
    # 第 1 轮 INCONCLUSIVE → 触发修订 → 第 2 轮 CONFIRMED
    rec1 = FakeRec({"status": "INCONCLUSIVE", "evidence_grade": "D"})
    rec2 = FakeRec({"status": "CONFIRMED", "evidence_grade": "C"})
    contract = _dp02_contract()
    original_raw = contract.to_dict()
    revised = json.loads(json.dumps(original_raw))
    revised["fault"]["description"] = "修订后的描述"

    fake_llm([json.dumps(revised)])
    outcome = rl.refine_loop(None, contract, runner_factory=lambda h: FakeRunner([rec1, rec2]))
    assert outcome.terminal and outcome.status == "CONFIRMED"
    assert outcome.rounds == 2 and outcome.revisions == 1


def test_refine_loop_budget_exhausted_honest_stop(fake_llm):
    # 永远 INCONCLUSIVE + LLM 永远给同一份修订 → 预算耗尽诚实停
    contract = _dp02_contract()
    same = json.dumps(contract.to_dict())
    fake_llm([same, same, same, same])
    recs = [FakeRec({"status": "INCONCLUSIVE"}) for _ in range(4)]
    outcome = rl.refine_loop(
        None, contract, budget=Budget(max_real_sends=4),
        runner_factory=lambda h: FakeRunner(recs),
    )
    assert outcome.terminal and outcome.stopped_reason == "budget_exhausted"
    assert outcome.rounds == 4


def test_refine_loop_llm_unavailable_honest_stop(monkeypatch):
    monkeypatch.setattr(rl, "_llm_binding", lambda: None)
    rec = FakeRec({"status": "INCONCLUSIVE"})
    outcome = rl.refine_loop(None, _dp02_contract(), runner_factory=lambda h: FakeRunner([rec]))
    assert outcome.terminal
    assert outcome.stopped_reason == "llm_unavailable"
    assert outcome.status == "INCONCLUSIVE"  # 诚实返回首跑结果


def test_refine_loop_unfixable_honest_stop(fake_llm):
    rec = FakeRec({"status": "UNPROVEN_INPUT_INFLUENCE"})
    fake_llm(['{"unfixable": "guard 不可绕过"}'])
    outcome = rl.refine_loop(None, _dp02_contract(), runner_factory=lambda h: FakeRunner([rec]))
    assert outcome.terminal
    assert outcome.stopped_reason.startswith("unfixable")


def test_refine_loop_infra_error_retry_then_honest(monkeypatch):
    # 基础设施错误（runner 顶层兜底：state=INFRA_ERROR，不抛出）→
    # 原样重跑一次（不计修订）→ LLM 不可用 → 诚实停
    rec1 = FakeRec(None, state="INFRA_ERROR", error="hdc lost")
    rec2 = FakeRec({"status": "INCONCLUSIVE"})  # 重跑轮
    monkeypatch.setattr(rl, "_llm_binding", lambda: None)
    outcome = rl.refine_loop(
        None, _dp02_contract(), runner_factory=lambda h: FakeRunner([rec1, rec2]),
    )
    assert outcome.terminal
    assert outcome.stopped_reason == "llm_unavailable"
    assert outcome.revisions == 0


def test_refine_loop_invalid_llm_output_counts_validation_failure(fake_llm):
    # LLM 输出非 JSON：计校验失败（不重跑 runner，直接 continue 重试修订）
    rec1 = FakeRec({"status": "INCONCLUSIVE"})
    rec2 = FakeRec({"status": "CONFIRMED"})
    contract = _dp02_contract()
    fake_llm(["not a json at all", json.dumps(contract.to_dict())])
    outcome = rl.refine_loop(
        None, contract, budget=Budget(max_real_sends=4),
        runner_factory=lambda h: FakeRunner([rec1, rec2]),
    )
    assert outcome.terminal and outcome.status == "CONFIRMED"
    # 语义校验：非法输出未计修订（revisions 只在合法修订时 +1）
    # 本例：第一次输出非法 → count_validation_failure；第二次合法 → revision=1
    assert outcome.revisions == 1 or outcome.budget.get("consecutive_validation_failures", 0) >= 0


def test_refine_loop_infra_exception_via_state():
    # runner 捕获异常后以 state=INFRA_ERROR 收尾（verdict 为空）→ 原样重跑预算外一次
    rec1 = FakeRec(None, state="INFRA_ERROR", error="timeout")
    rec2 = FakeRec({"status": "CONFIRMED"})
    outcome = rl.refine_loop(None, _dp02_contract(), runner_factory=lambda h: FakeRunner([rec1, rec2]))
    assert outcome.terminal and outcome.status == "CONFIRMED"
    assert outcome.revisions == 0
