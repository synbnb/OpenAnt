"""判定引擎（§12）：三层正交状态 + status 派生 + 证据分级。

status 派生表（§12.1）——唯一入口，禁止调用方自行拼 status：
  INPUT_DELIVERED + SINK_CONTROLLED   + EFFECT_OBSERVED → CONFIRMED
  INPUT_DELIVERED + SINK_CONTROLLED   + EFFECT_ABSENT   → NOT_REPRODUCED
  INPUT_DELIVERED + SINK_REACHED_UNCONTROLLED           → UNPROVEN_INPUT_INFLUENCE
  INPUT_DELIVERED + SINK_UNKNOWN                        → INCONCLUSIVE
  INPUT_REJECTED / INPUT_NOT_SENT                       → BLOCKED_<reason>
"""

from __future__ import annotations

from .models import OracleResult, Verdict

# oracle 的 effect_observed / forms 全过 → EFFECT_OBSERVED；全不过 → EFFECT_ABSENT；部分/未执行 → EFFECT_UNKNOWN
SINK_CONTROLLED = "SINK_CONTROLLED"
SINK_REACHED_UNCONTROLLED = "SINK_REACHED_UNCONTROLLED"
SINK_UNKNOWN = "SINK_UNKNOWN"

EFFECT_OBSERVED = "EFFECT_OBSERVED"
EFFECT_ABSENT = "EFFECT_ABSENT"
EFFECT_UNKNOWN = "EFFECT_UNKNOWN"


def derive_effect(oracle: OracleResult | None) -> str:
    if oracle is None:
        return EFFECT_UNKNOWN
    if oracle.effect_observed:
        return EFFECT_OBSERVED
    if oracle.forms and all(not v for v in oracle.forms.values()):
        return EFFECT_ABSENT
    return EFFECT_UNKNOWN


def derive_influence(
    reachability: str,
    effect: str,
    oracle: OracleResult | None = None,
    *,
    influence_blocker: str = "",
) -> str:
    """从 reachability + 效果信号推 influence（§12.1）。

    - oracle 判定 effect_observed=True → SINK_CONTROLLED（oracle 语义本身即
      "该输入产生声明效果"，不依赖 effect 的三值聚合）；
    - effect=EFFECT_ABSENT 且基线成立 → SINK_CONTROLLED：oracle 全部 form 明确
      判定"该输入未产生声明效果"，这本身证明 sink 被到达且行为受输入支配
      （差分预言机的否定结果仍是受控证据），对应派生表的 NOT_REPRODUCED；
    - 效果缺失但存在 blocker（policy/permission/check）→ SINK_REACHED_UNCONTROLLED；
    - 其余 → SINK_UNKNOWN。
    """
    if oracle is not None and oracle.effect_observed:
        return SINK_CONTROLLED
    if reachability == "INPUT_DELIVERED":
        if effect == EFFECT_OBSERVED:
            return SINK_CONTROLLED
        if effect == EFFECT_ABSENT and oracle is not None and not influence_blocker:
            return SINK_CONTROLLED
        if influence_blocker:
            return SINK_REACHED_UNCONTROLLED
        return SINK_UNKNOWN
    if reachability == "INPUT_REJECTED":
        return SINK_REACHED_UNCONTROLLED if influence_blocker else SINK_UNKNOWN
    return SINK_UNKNOWN


def derive_status(
    reachability: str,
    influence: str,
    effect: str,
    *,
    baselined: bool,
) -> str:
    if reachability == "INPUT_DELIVERED":
        if influence == SINK_CONTROLLED:
            if effect == EFFECT_OBSERVED:
                return "CONFIRMED"
            if effect == EFFECT_ABSENT:
                return "NOT_REPRODUCED" if baselined else "INCONCLUSIVE"
            return "INCONCLUSIVE"
        if influence == SINK_REACHED_UNCONTROLLED:
            return "UNPROVEN_INPUT_INFLUENCE"
        return "INCONCLUSIVE"
    return f"BLOCKED_{reachability}"


def evidence_grade(
    *,
    execution_identity: str,
    effect: str,
    oracle_strength: str = "strong",
) -> str:
    """§12.2：由身份与预言机强度共同决定，不可被上层覆盖。"""
    if effect != EFFECT_OBSERVED:
        return "E" if oracle_strength == "none" else "D"
    if execution_identity == "hap_app":
        return "A" if oracle_strength == "strong" else "B"
    if execution_identity in ("debug_app", "synthetic_uid", "synthetic_domain"):
        return "B"
    if execution_identity == "root_su":
        return "C"
    return "E"


def build_verdict(
    *,
    contract_id: str,
    run_id: str,
    reachability: str,
    oracle: OracleResult | None,
    execution_identity: str = "root_su",
    influence_blocker: str = "",
    baselined: bool = False,
    oracle_strength: str = "strong",
    status_reason_code: str = "",
    gap: str = "",
    limitations: list[str] | None = None,
    code_deviation: list[str] | None = None,
) -> Verdict:
    effect = derive_effect(oracle)
    influence = derive_influence(reachability, effect, oracle, influence_blocker=influence_blocker)
    status = derive_status(reachability, influence, effect, baselined=baselined)
    return Verdict(
        contract_id=contract_id,
        run_id=run_id,
        reachability=reachability,
        influence=influence,
        effect=effect,
        status=status,
        influence_blocker=influence_blocker,
        status_reason_code=status_reason_code,
        evidence_grade=evidence_grade(
            execution_identity=execution_identity, effect=effect, oracle_strength=oracle_strength
        ),
        oracle=oracle,
        limitations=list(limitations or []),
        code_deviation=list(code_deviation or []),
        gap=gap,
    )
