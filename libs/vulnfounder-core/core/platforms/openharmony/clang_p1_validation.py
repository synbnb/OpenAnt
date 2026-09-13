"""P1 Clang 批量提取验收与未决调用点对照。

本模块只生成诊断报告，不修改原生调用图、数据集或可达性结果。它把三类
信息放到同一份可复查产物中：

* 原始调用点缺口台账（按调用点统计，而不是按候选记录数统计）；
* `clang_batch_extractor` 的语义事实、拒绝原因和 caller 未入函数索引；
* 若干已知关系的控制性对照。

手工重建编译命令只能证明“在该命令和该源码快照下取得了语义绑定”。除非
构建状态明确表示产品配置已验证，否则报告将其标成 candidate-only，不能把
它解释为产品 strict 可达证据。
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1

DEFAULT_CONTROL_RELATIONS: tuple[dict[str, Any], ...] = (
    {
        "name": "EditorRecv -> GetResult",
        "caller_id": "sp_thread_socket.cpp:SpThreadSocket::EditorRecv",
        "callee_id": "control_call_cmd.cpp:ControlCallCmd::GetResult",
        "file": "sp_thread_socket.cpp",
        "line": 378,
        "expression": "controlCallCmd.GetResult(vec)",
    },
    {
        "name": "ExecCommand -> InitDataCsv",
        "caller_id": "smartperf_command.cpp:SmartPerfCommand::ExecCommand",
        "callee_id": "task_manager.cpp:TaskManager::InitDataCsv",
        "file": "smartperf_command.cpp",
        "line": 168,
        "expression": "taskMgr_.InitDataCsv()",
    },
    {
        "name": "main -> ExecCommand",
        "caller_id": "smartperf_main.cpp:main",
        "callee_id": "smartperf_command.cpp:SmartPerfCommand::ExecCommand",
        "file": "smartperf_main.cpp",
        "line": 262,
        "expression": "cmd.ExecCommand()",
    },
)


def _load(value: Mapping[str, Any] | str | Path) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    with Path(value).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, Mapping):
        raise ValueError(f"expected JSON object: {value}")
    return payload


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _basename(value: Any) -> str:
    return _text(value).replace("\\", "/").rsplit("/", 1)[-1]


def _line(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalise_expression(value: Any) -> str:
    return " ".join(_text(value).split())


def _explicit_true(value: Any) -> bool:
    if value is True:
        return True
    return _text(value).lower() in {"1", "true", "yes"}


def _site_matches_edge(site: Mapping[str, Any], edge: Mapping[str, Any]) -> bool:
    expected_caller = _text(site.get("caller_id"))
    actual_source = _text(edge.get("source_id"))
    if expected_caller and actual_source and actual_source != "function:" + expected_caller:
        return False
    attrs = edge.get("attributes")
    attrs = attrs if isinstance(attrs, Mapping) else {}
    callsite = attrs.get("call_site")
    callsite = callsite if isinstance(callsite, Mapping) else {}
    if _basename(site.get("file")) != _basename(callsite.get("file")):
        return False
    site_start = _line(site.get("line_start", site.get("line")))
    site_end = _line(site.get("line_end", site_start), site_start)
    edge_line = _line(callsite.get("line"))
    if edge_line < site_start or edge_line > max(site_start, site_end):
        return False
    site_expr = _normalise_expression(site.get("expression"))
    edge_expr = _normalise_expression(callsite.get("expression"))
    if not site_expr or not edge_expr:
        return True
    return site_expr in edge_expr or edge_expr in site_expr


def _edge_view(edge: Mapping[str, Any]) -> dict[str, Any]:
    attrs = edge.get("attributes")
    attrs = attrs if isinstance(attrs, Mapping) else {}
    callsite = attrs.get("call_site")
    callsite = dict(callsite) if isinstance(callsite, Mapping) else {}
    raw_evidence = edge.get("evidence")
    evidence = [dict(item) for item in raw_evidence if isinstance(item, Mapping)] \
        if isinstance(raw_evidence, list) else []
    return {
        "source_id": _text(edge.get("source_id")),
        "target_id": _text(edge.get("target_id")),
        "call_site": callsite,
        "evidence": evidence,
        "edge_kind": _text(attrs.get("edge_kind")),
        "resolver": _text(attrs.get("resolver")),
        "binding_status": _text(attrs.get("binding_status")),
        "reachability_tier": _text(attrs.get("reachability_tier")),
        "build_status": _text(attrs.get("build_status")),
        "build_admission": _text(attrs.get("build_admission")),
        "source_revision": _text(attrs.get("source_revision")),
    }


def _batch_scope(batch: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    raw = batch.get("file_results")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, Mapping):
                name = _basename(item.get("file"))
                if name:
                    result.add(name)
    return result


def _unindexed_summary(batch: Mapping[str, Any]) -> dict[str, Any]:
    raw = batch.get("unindexed_calls")
    calls = [item for item in raw if isinstance(item, Mapping)] if isinstance(raw, list) else []
    by_file = Counter(_basename(item.get("file")) for item in calls)
    return {
        "count": len(calls),
        "by_file": dict(sorted((key, value) for key, value in by_file.items() if key)),
        "samples": [dict(item) for item in calls[:20]],
    }


def _control_result(
    relation: Mapping[str, Any],
    ledger_sites: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    batch_scope: set[str],
) -> dict[str, Any]:
    file_name = _basename(relation.get("file"))
    line = _line(relation.get("line"))
    expression = _normalise_expression(relation.get("expression"))
    ledger = next(
        (
            site for site in ledger_sites
            if _text(site.get("caller_id")) == _text(relation.get("caller_id"))
            and _basename(site.get("file")) == file_name
            and _line(site.get("line_start")) <= line <= _line(site.get("line_end"), line)
            and _normalise_expression(site.get("expression")) == expression
        ),
        None,
    )
    matched = [edge for edge in edges if _site_matches_edge(relation, edge)]
    matching_target = [
        edge for edge in matched
        if _text(edge.get("target_id")) == "function:" + _text(relation.get("callee_id"))
    ]
    return {
        "name": _text(relation.get("name")),
        "caller_id": _text(relation.get("caller_id")),
        "callee_id": _text(relation.get("callee_id")),
        "file": file_name,
        "line": line,
        "expression": expression,
        "ledger_status": {
            "found": ledger is not None,
            "site_id": _text(ledger.get("site_id")) if ledger else None,
            "binding_status": _text(ledger.get("binding_status")) if ledger else None,
            "graph_status": _text(ledger.get("graph_status")) if ledger else None,
            "candidate_target_ids": list(ledger.get("candidate_target_ids", [])) if ledger else [],
        },
        "batch_scope": file_name in batch_scope,
        "batch_match": bool(matching_target),
        "batch_match_count": len(matching_target),
        "matched_edges": [_edge_view(edge) for edge in matching_target],
        "interpretation": (
            "native_graph_control_and_manual_clang_candidate_match"
            if ledger and _text(ledger.get("graph_status")) == "linked" and matching_target
            else "native_graph_control_only_outside_current_batch"
            if ledger and _text(ledger.get("graph_status")) == "linked" and not matching_target
            else "requires_manual_review"
        ),
    }


def build_clang_batch_acceptance_report(
    ledger: Mapping[str, Any] | str | Path,
    gap_report: Mapping[str, Any] | str | Path,
    batch: Mapping[str, Any] | str | Path,
    *,
    source_revision: str | None = None,
    control_relations: Sequence[Mapping[str, Any]] = DEFAULT_CONTROL_RELATIONS,
) -> dict[str, Any]:
    """Build a reproducible report correlating Clang facts with gap sites."""
    ledger_payload = _load(ledger)
    gap_payload = _load(gap_report)
    batch_payload = _load(batch)
    ledger_sites = [
        item for item in ledger_payload.get("call_sites", [])
        if isinstance(item, Mapping)
    ]
    gap_sites = [
        item for item in gap_payload.get("sites", [])
        if isinstance(item, Mapping) and bool(item.get("ledger_unrepaired"))
    ]
    edges = [item for item in batch_payload.get("edges", []) if isinstance(item, Mapping)]
    batch_scope = _batch_scope(batch_payload)

    site_results: list[dict[str, Any]] = []
    outcome_counts: Counter[str] = Counter()
    for site in gap_sites:
        matches = [edge for edge in edges if _site_matches_edge(site, edge)]
        in_scope = _basename(site.get("file")) in batch_scope
        if matches:
            outcome = "semantic_fact_observed_candidate_only"
        elif in_scope:
            outcome = "in_batch_scope_not_matched"
        else:
            outcome = "outside_batch_scope"
        outcome_counts[outcome] += 1
        site_results.append({
            "site_id": _text(site.get("site_id")),
            "caller_id": _text(site.get("caller_id")),
            "file": _text(site.get("file")),
            "line_start": _line(site.get("line_start")),
            "line_end": _line(site.get("line_end"), _line(site.get("line_start"))),
            "expression": _text(site.get("expression")),
            "original_reasons": list(site.get("reason_codes", [])),
            "batch_scope": in_scope,
            "outcome": outcome,
            "matched_edges": [_edge_view(edge) for edge in matches],
        })

    batch_summary = batch_payload.get("batch_summary")
    batch_summary = dict(batch_summary) if isinstance(batch_summary, Mapping) else {}
    overlay_summary = batch_payload.get("summary")
    overlay_summary = dict(overlay_summary) if isinstance(overlay_summary, Mapping) else {}
    rejected = [item for item in batch_payload.get("rejected", []) if isinstance(item, Mapping)]
    rejection_counts = Counter(_text(item.get("reason")) for item in rejected)
    report_revision = source_revision or _text(batch_payload.get("source_revision")) or "unknown"
    build_status = _text(batch_payload.get("build_status")) or "unknown"
    strict_admission = build_status in {"compile_database", "complete", "verified"}
    product_config_verified = _explicit_true(
        batch_payload.get("product_config_verified")
        or batch_payload.get("product_configuration_verified")
    )

    report = {
        "schema_version": SCHEMA_VERSION,
        "report_type": "openharmony_clang_p1_batch_acceptance",
        "repository": _text(batch_payload.get("repository")),
        "source_revision": report_revision,
        "scope": {
            "batch_files": sorted(batch_scope),
            "unresolved_input_sites": len(gap_sites),
            "unresolved_sites_in_batch_scope": sum(
                1 for site in gap_sites if _basename(site.get("file")) in batch_scope
            ),
            "note": "未决站点按调用点计数；候选目标数量不等于缺口数量。",
        },
        "input_provenance": {
            "gap_report_summary": dict(gap_payload.get("summary", {}))
            if isinstance(gap_payload.get("summary"), Mapping) else {},
            "batch_experiment": dict(batch_payload.get("experiment", {}))
            if isinstance(batch_payload.get("experiment"), Mapping) else {},
        },
        "build_context": {
            "status": build_status,
            "strict_admission": strict_admission,
            "product_config_verified": product_config_verified,
            "admission": "strict_for_concrete_configuration" if strict_admission else "candidate_only",
            "interpretation": (
                "当前上下文可复现所提供的具体配置；产品配置等价性仍需显式 provenance 证明"
                if strict_admission
                else "手工重建或未知上下文，仅证明该命令下的语义绑定，不进入产品 strict 图"
            ),
        },
        "batch_summary": batch_summary,
        "overlay_summary": overlay_summary,
        "rejection_reason_counts": dict(sorted(rejection_counts.items())),
        "unindexed_callers": _unindexed_summary(batch_payload),
        "unresolved_site_outcomes": {
            "counts": dict(sorted(outcome_counts.items())),
            "sites": site_results,
        },
        "control_relations": [
            _control_result(relation, ledger_sites, edges, batch_scope)
            for relation in control_relations
        ],
        "conclusions": [
            "四个翻译单元均成功执行批量 Clang 提取，但这不等于完整产品构建配置已验证。",
            "manual_rebuild/reconstructed_candidate 事实只进入 candidate-only 视图；必须取得匹配产品 compile database 后才能作为 strict 入图证据。",
            "未决站点在本批次范围外的部分没有被判定为不可达，只记录为本轮未覆盖。",
            "caller_not_in_index 是独立诊断维度：它表示 Clang 发现了调用上下文，但当前函数索引没有对应 caller，不能静默当作没有调用。",
        ],
    }
    return report


def write_clang_batch_acceptance_report(
    output_path: str | Path,
    ledger: Mapping[str, Any] | str | Path,
    gap_report: Mapping[str, Any] | str | Path,
    batch: Mapping[str, Any] | str | Path,
    **kwargs: Any,
) -> dict[str, Any]:
    report = build_clang_batch_acceptance_report(ledger, gap_report, batch, **kwargs)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


__all__ = [
    "DEFAULT_CONTROL_RELATIONS",
    "SCHEMA_VERSION",
    "build_clang_batch_acceptance_report",
    "write_clang_batch_acceptance_report",
]
