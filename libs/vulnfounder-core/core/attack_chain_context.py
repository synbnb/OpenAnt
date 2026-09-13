"""调用点级攻击链上下文的保守数据契约。

``reachability_context`` 里的入口路径是函数级的静态图路径。它能说明图上
存在一条从入口到目标的路径，但不能说明某一个危险调用点的参数由哪个外部
输入控制，也不能自动证明异步调度、共享状态和动态分派成立。本模块提供一
个很小的、可向后兼容的契约，把这两个维度明确分开：

* ``generic_entry_path_found``：有效调用图是否找到通用入口路径；
* ``attack_chain_context``：是否已经针对具体调用点、危险参数和 source-to-sink
  关系完成证据组织。当前没有这类证据时必须写成 ``not_evaluated``，不能把
  函数级路径升级为完整攻击链。这个维度属于 Stage 2 的定向验证，不是
  Stage 1 的准入条件。

``stage_context_from_unit`` 会把前置结构可达性和 Stage 2 数据流状态拆成
两个明确视图。Stage 1 仍然负责漏洞检测；“参数数据流尚未追踪”不会被解释
成不可达或安全。

这里的内容可能来自模型或其它分析阶段，均按不可信辅助数据处理。规范化仅
限制形状和长度，不为关系添加语义证明；严格校验将在后续的调用点/数据流求
证阶段完成。
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SCHEMA_VERSION = 1
# Keep more than the prompt renders.  A callee such as ``SPUtils::LoadCmd``
# can have dozens of callers; truncating in source order can hide the one
# caller that belongs to a socket handler.  The loader applies a deterministic
# boundary/dispatch relevance order before this cap.
MAX_CALLSITE_CONTEXTS = 24
MAX_STEPS = 32
MAX_EVIDENCE = 24
MAX_TEXT = 1200

_STATUSES = {"not_evaluated", "incomplete", "complete", "blocked", "unknown"}


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    # Newlines are kept in JSON evidence but never allowed to grow without a
    # bound. Prompt rendering performs an additional single-line collapse.
    return str(value)[:limit]


def _list(value: Any, limit: int) -> list[Any]:
    if not isinstance(value, (list, tuple)):
        return []
    return list(value)[:limit]


def _string_list(value: Any, limit: int) -> list[str]:
    return [item for item in (_text(raw, 500).strip() for raw in _list(value, limit)) if item]


def _evidence(value: Any) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for raw in _list(value, MAX_EVIDENCE):
        if isinstance(raw, Mapping):
            item: dict[str, Any] = {}
            for key in (
                "id", "kind", "file", "path", "line_start", "line_end", "symbol",
                "excerpt", "relation", "status", "source",
            ):
                if raw.get(key) in (None, "", []):
                    continue
                value = raw.get(key)
                item[key] = _text(value) if isinstance(value, str) else value
            if item:
                output.append(item)
        elif raw not in (None, ""):
            output.append({"excerpt": _text(raw)})
    return output


def _flow_fact(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    output: dict[str, Any] = {}
    evidence = raw.get("evidence") if isinstance(raw.get("evidence"), Mapping) else {}
    for key in (
        "fact_id", "fact_kind", "status", "confidence", "caller_id", "target_id",
        "file", "line_start", "line_end", "expression", "source",
    ):
        if raw.get(key) not in (None, "", []):
            value = raw.get(key)
            output[key] = _text(value) if isinstance(value, str) else value
    # Object-flow artifacts use ``kind`` and often keep source positions only
    # in their evidence block.  Normalize those aliases so Stage 1 receives
    # the actual relationship and source line instead of an opaque fact ID.
    if not output.get("fact_kind") and raw.get("kind") not in (None, ""):
        output["fact_kind"] = _text(raw.get("kind"), 200)
    for field in ("file", "line_start", "line_end"):
        if output.get(field) in (None, "") and evidence.get(field) not in (None, ""):
            output[field] = evidence.get(field)
    if not output.get("source") and evidence.get("text") not in (None, ""):
        output["source"] = _text(evidence.get("text"), 700)
    for key in ("value", "attributes", "evidence"):
        value = raw.get(key)
        if isinstance(value, Mapping):
            # Keep a small, JSON-safe projection; values are evidence, not
            # prompt instructions, and the renderer will collapse text.
            compact: dict[str, Any] = {}
            for field, field_value in list(value.items())[:16]:
                if isinstance(field_value, (str, int, float, bool)):
                    compact[_text(field, 100)] = _text(field_value) if isinstance(field_value, str) else field_value
                elif isinstance(field_value, list):
                    if all(isinstance(item, Mapping) for item in field_value[:MAX_STEPS]):
                        compact_items = []
                        for item in field_value[:MAX_STEPS]:
                            compact_items.append({
                                _text(item_key, 80): (
                                    _text(item_value, 300)
                                    if isinstance(item_value, str) else item_value
                                )
                                for item_key, item_value in list(item.items())[:12]
                                if item_value not in (None, "", [])
                            })
                        compact[_text(field, 100)] = compact_items
                    else:
                        compact[_text(field, 100)] = _string_list(field_value, MAX_STEPS)
            if compact:
                output[key] = compact
    return output or None


def _callsite(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    output: dict[str, Any] = {}
    for key in (
        "callsite_id", "id", "location", "file", "path", "line_start", "line_end",
        "expression", "caller", "callee", "call_type", "dispatch_type",
        "binding_status", "dispatch_status", "graph_status", "candidate_completeness",
        "target_set_completeness", "binding_basis",
        "dangerous_operation", "dangerous_parameter", "parameter", "sink",
        "source", "input_source", "status", "assumptions", "missing_evidence",
    ):
        if raw.get(key) in (None, "", []):
            continue
        value = raw.get(key)
        if isinstance(value, str):
            output[key] = _text(value)
        elif key in {"assumptions", "missing_evidence"}:
            output[key] = _string_list(value, MAX_STEPS)
        else:
            output[key] = value
    for key in ("candidate_target_ids", "linked_target_ids"):
        values = _string_list(raw.get(key), 32)
        if values:
            output[key] = values
    for key in ("ordered_steps", "cross_boundary_edges"):
        values = _string_list(raw.get(key), MAX_STEPS)
        if values:
            output[key] = values
    for key in ("data_flow", "state_flow", "process_output", "cross_process"):
        raw_flow = raw.get(key)
        if isinstance(raw_flow, Mapping):
            flow: dict[str, list[str]] = {}
            for field, values in raw_flow.items():
                items = _string_list(values, MAX_STEPS)
                if items:
                    flow[_text(field, 100)] = items
            if flow:
                output[key] = flow
        else:
            values = _string_list(raw_flow, MAX_STEPS)
            if values:
                output[key] = values
    evidence = _evidence(raw.get("evidence"))
    if evidence:
        output["evidence"] = evidence
    flow_facts = []
    for raw_fact in _list(raw.get("flow_facts"), MAX_EVIDENCE):
        fact = _flow_fact(raw_fact)
        if fact:
            flow_facts.append(fact)
    if flow_facts:
        output["flow_facts"] = flow_facts
    return output or None


def normalize_attack_chain_context(raw: Any = None) -> dict[str, Any]:
    """Normalize optional callsite-level evidence without upgrading its meaning."""
    if not isinstance(raw, Mapping):
        raw = {}
    status = _text(raw.get("status") or raw.get("context_status"), 64).lower()
    if status not in _STATUSES:
        status = "not_evaluated"
    complete = raw.get("complete")
    if not isinstance(complete, bool):
        complete = True if status == "complete" else (False if status in {"incomplete", "blocked"} else None)
    contexts: list[dict[str, Any]] = []
    candidates = raw.get("callsite_contexts")
    if not isinstance(candidates, list):
        candidates = raw.get("callsites")
    for candidate in _list(candidates, MAX_CALLSITE_CONTEXTS):
        normalized = _callsite(candidate)
        if normalized:
            contexts.append(normalized)
    missing = _string_list(raw.get("missing_evidence") or raw.get("missing"), MAX_STEPS)
    if status == "not_evaluated" and not missing:
        missing = [
            "target_callsite_not_selected",
            "dangerous_parameter_not_identified",
            "source_to_sink_dataflow_not_traced",
        ]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "complete": complete,
        "callsite_contexts": contexts,
        "missing_evidence": missing,
        "evidence": _evidence(raw.get("evidence")),
        "provenance": _text(raw.get("provenance"), 300) or "not_provided",
    }


def context_from_unit(unit: Mapping[str, Any]) -> dict[str, Any]:
    """Read the optional structured context carried by a dataset unit."""
    raw = unit.get("attack_chain_context")
    if not isinstance(raw, Mapping):
        raw = unit.get("attack_chain")
    if not isinstance(raw, Mapping):
        raw = unit.get("source_sink_context")
    normalized = normalize_attack_chain_context(raw)
    if normalized["status"] != "not_evaluated":
        return normalized

    # The single-shot enhancer already emits a bounded data_flow object.  It
    # is not a verified attack chain and usually lacks a precise callsite, but
    # preserving it as an incomplete candidate is more useful than silently
    # discarding the source/state hints before Stage 1.
    for context_key in ("llm_context", "agent_context"):
        context = unit.get(context_key)
        if not isinstance(context, Mapping):
            continue
        data_flow = context.get("data_flow")
        if not isinstance(data_flow, Mapping):
            continue
        flow = {}
        for field in ("inputs", "outputs", "tainted_variables", "security_relevant_flows"):
            values = _string_list(data_flow.get(field), MAX_STEPS)
            if values:
                flow[field] = values
        if not flow:
            continue
        return normalize_attack_chain_context({
            "status": "incomplete",
            "complete": False,
            "callsite_contexts": [{
                "status": "candidate",
                "source": "; ".join(flow.get("inputs", [])),
                "sink": "; ".join(flow.get("outputs", [])),
                "data_flow": flow,
                "state_flow": {
                    "tainted_variables": flow.get("tainted_variables", []),
                } if flow.get("tainted_variables") else {},
                "ordered_steps": flow.get("security_relevant_flows", []),
                "assumptions": [
                    "target_callsite_not_selected",
                    "dangerous_parameter_sink_binding_unverified",
                ],
            }],
            "missing_evidence": [
                "target_callsite_not_selected",
                "dangerous_parameter_sink_binding_unverified",
                "source_to_sink_dataflow_not_traced",
            ],
            "provenance": f"{context_key}:data_flow",
        })
    return normalized


def stage_context_from_unit(unit: Mapping[str, Any]) -> dict[str, Any]:
    """Return phase-separated context for Stage 1 and Stage 2.

    The reachability pass answers a structural question: whether the target has
    a strict/candidate/root path in the effective graph.  The callsite attack
    chain answers a different and more expensive question: whether an external
    value reaches a particular dangerous parameter.  The latter belongs to
    Stage 2 and must not remove a unit from Stage 1 analysis.

    The result is derived from persisted artifacts only.  It does not promote
    model signals or fabricate an entry path.
    """
    if not isinstance(unit, Mapping):
        unit = {}
    lineage = unit.get("reachability_context")
    if not isinstance(lineage, Mapping):
        lineage = {}

    graph_status = _text(lineage.get("status"), 64).lower()
    strict_path = (
        lineage.get("generic_entry_path_found") is True
        or bool(lineage.get("entry_path_ids"))
        or graph_status == "path_found"
    )
    candidate_path = (
        lineage.get("candidate_entry_path_found") is True
        or bool(lineage.get("candidate_entry_path_ids"))
        or graph_status == "candidate_path_found"
    )
    if strict_path:
        structural_status = "strict"
    elif candidate_path:
        structural_status = "candidate"
    elif graph_status == "root":
        structural_status = "root"
    else:
        structural_status = "unknown"

    structural_missing = list(lineage.get("missing_upstream_evidence") or [])
    if not structural_missing and structural_status == "candidate":
        structural_missing = list(lineage.get("candidate_missing_evidence") or [])
    if not structural_missing and structural_status == "unknown":
        structural_missing = ["external_or_structural_entry_path_not_proven"]

    # ``reachability_context`` is the persisted container produced before the
    # unit reaches enhancement/Stage 1.  Accept its nested attack-chain object
    # as well as the newer unit-level form used by enhanced datasets.
    context_input = unit
    if not unit.get("attack_chain_context") and lineage.get("attack_chain_context"):
        context_input = dict(unit)
        context_input["attack_chain_context"] = lineage.get("attack_chain_context")
    attack_chain = context_from_unit(context_input)
    dataflow_status = attack_chain.get("status") or "not_evaluated"
    dataflow_missing = list(attack_chain.get("missing_evidence") or [])

    return {
        "schema_version": 1,
        "stage1": {
            "status": structural_status,
            "graph_status": graph_status or "unknown",
            "generic_entry_path_found": bool(strict_path),
            "candidate_entry_path_found": bool(candidate_path),
            "top_level_entry": lineage.get("top_level_entry"),
            "entry_path_ids": [
                list(path)[:24]
                for path in (lineage.get("entry_path_ids") or [])[:3]
                if isinstance(path, list)
            ],
            "candidate_entry_path_ids": [
                list(path)[:24]
                for path in (lineage.get("candidate_entry_path_ids") or [])[:3]
                if isinstance(path, list)
            ],
            "missing_evidence": _string_list(structural_missing, MAX_STEPS),
            # This is informational and only describes the data-flow gate.  A
            # processing-level filter may still exclude an unknown structural
            # path; parameter data-flow status itself never excludes a unit.
            "analysis_allowed_if_selected": True,
            "parameter_dataflow_is_stage1_gate": False,
            # Backward-compatible alias used by early diagnostic artifacts.
            "analysis_allowed": True,
        },
        "stage2": {
            "parameter_dataflow_status": dataflow_status,
            "parameter_dataflow_complete": attack_chain.get("complete"),
            "missing_evidence": _string_list(dataflow_missing, MAX_STEPS),
            "callsite_count": len(attack_chain.get("callsite_contexts") or []),
            "callsite_context": attack_chain,
        },
    }


__all__ = [
    "SCHEMA_VERSION",
    "context_from_unit",
    "normalize_attack_chain_context",
    "stage_context_from_unit",
]
