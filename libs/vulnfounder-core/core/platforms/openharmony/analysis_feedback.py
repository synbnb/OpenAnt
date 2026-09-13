"""OpenHarmony P3 分析反馈事实（不自动改图）。

上下文增强和 Stage 1 可能会发现原始调用图没有表达的上游、下游或入口
线索。过去这些线索只停留在单元结果里，下一次扫描无法区分它们是源码事实、
模型候选还是仅仅是一个判断。这个模块把它们归一化为可审计的反馈事实，并
关联当前图、源码和构建版本。

这里的 ``candidate`` 事实只是调度/审计输入，不会修改 native/effective
call graph，也不会改变当前扫描的 strict reachable 集合。只有后续绑定、类型、
注册关系和配置核验都通过，才可以由有效图生成器接纳。
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from utilities.file_io import read_json, write_json


SCHEMA_VERSION = 1
FEEDBACK_FILENAME = "analysis_feedback.json"
MAX_FACTS_PER_UNIT = 32


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple, set)) else []


def _unit_source(unit: Mapping[str, Any]) -> dict[str, Any]:
    code = unit.get("code") if isinstance(unit.get("code"), Mapping) else {}
    origin = code.get("primary_origin") if isinstance(code.get("primary_origin"), Mapping) else {}
    metadata = unit.get("metadata") if isinstance(unit.get("metadata"), Mapping) else {}
    return {
        "file": (
            origin.get("file") or origin.get("source_file")
            or unit.get("file_path") or unit.get("file")
            or metadata.get("file_path") or metadata.get("file")
        ),
        "line_start": (
            origin.get("start_line") or unit.get("start_line")
            or metadata.get("start_line")
        ),
        "line_end": (
            origin.get("end_line") or unit.get("end_line")
            or metadata.get("end_line")
        ),
        "source_revision": unit.get("source_revision"),
    }


def _normalise_ref(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, str):
        value = raw.strip()
        return {"id": value, "reason": "model_or_enhancer_reference"} if value else None
    if not isinstance(raw, Mapping):
        return None
    value = raw.get("id") or raw.get("function_id") or raw.get("name") or raw.get("target")
    value = _text(value)
    if not value:
        return None
    return {
        "id": value,
        "reason": _text(raw.get("reason")) or "model_or_enhancer_reference",
        **({"file": raw.get("file")} if raw.get("file") else {}),
        **({"line": raw.get("line")} if raw.get("line") else {}),
    }


def _result_by_unit(results: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    result = results if isinstance(results, Mapping) else {}
    rows = result.get("results", [])
    output: dict[str, Mapping[str, Any]] = {}
    if not isinstance(rows, list):
        return output
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        unit_id = _text(row.get("unit_id")) or _text(row.get("route_key"))
        if unit_id:
            output[unit_id] = row
    return output


def build_analysis_feedback(
    dataset: Mapping[str, Any] | None,
    *,
    results: Mapping[str, Any] | None = None,
    gap_tasks: Mapping[str, Any] | None = None,
    repository: str | None = None,
    source_revision: str | None = None,
    build_config_id: str | None = None,
    graph_versions: Iterable[str] = (),
) -> dict[str, Any]:
    """Build a bounded, source/provenance-labelled P3 feedback artifact."""
    source = dataset if isinstance(dataset, Mapping) else {}
    units = source.get("units", [])
    units = units if isinstance(units, list) else []
    result_by_unit = _result_by_unit(results)
    facts: list[dict[str, Any]] = []
    facts_by_kind: Counter[str] = Counter()
    path_units = 0
    unknown_path_units = 0
    stage1_counts: Counter[str] = Counter()

    for raw_unit in units:
        if not isinstance(raw_unit, Mapping):
            continue
        unit_id = _text(raw_unit.get("id"))
        if not unit_id:
            continue
        reach = raw_unit.get("reachability_context")
        reach = reach if isinstance(reach, Mapping) else {}
        if reach.get("entry_paths"):
            path_units += 1
        else:
            unknown_path_units += 1
        stage1 = result_by_unit.get(unit_id)
        if stage1:
            stage1_counts[_text(stage1.get("finding")) or "unknown"] += 1
            # A verdict is an observation of Stage 1, not a graph fact.
            facts.append({
                "fact_id": f"stage1:{unit_id}",
                "kind": "stage1_observation",
                "status": "observed",
                "source_unit_id": unit_id,
                "target_id": unit_id,
                "evidence": {
                    "finding": stage1.get("finding"),
                    "verdict": stage1.get("verdict"),
                    "categories": stage1.get("vulnerability_categories", []),
                },
                "source": _unit_source(raw_unit),
            })

        contexts: list[tuple[str, Any]] = []
        for context_key in ("agent_context", "llm_context"):
            context = raw_unit.get(context_key)
            if isinstance(context, Mapping):
                contexts.append((context_key, context))
        unit_fact_count = 0
        for context_key, context in contexts:
            for kind, field in (
                ("include_function", "include_functions"),
                ("additional_caller", "additional_callers"),
                ("missing_dependency", "missing_dependencies"),
            ):
                for raw_ref in _list(context.get(field)):
                    ref = _normalise_ref(raw_ref)
                    if ref is None or unit_fact_count >= MAX_FACTS_PER_UNIT:
                        continue
                    facts.append({
                        "fact_id": f"{kind}:{unit_id}:{unit_fact_count}",
                        "kind": kind,
                        "status": "candidate",
                        "source_unit_id": unit_id,
                        "target_id": ref.pop("id"),
                        "evidence": {
                            **ref,
                            "context_key": context_key,
                            "classification": context.get("security_classification"),
                            "confidence": context.get("confidence"),
                        },
                        "source": _unit_source(raw_unit),
                        "admission": "not_validated_no_graph_promotion",
                    })
                    facts_by_kind[kind] += 1
                    unit_fact_count += 1

        # Preserve a compact path observation so an incremental resolver can
        # prioritize facts that sit on a known entrance path.
        paths = _list(reach.get("entry_path_ids"))
        if paths:
            facts.append({
                "fact_id": f"entry_path:{unit_id}",
                "kind": "entry_path_observation",
                "status": "observed",
                "source_unit_id": unit_id,
                "target_id": unit_id,
                "evidence": {
                    "top_level_entry": reach.get("top_level_entry"),
                    "path_count": reach.get("path_count", len(paths)),
                    "path_ids": paths[:3],
                    "upstream_complete": reach.get("upstream_complete"),
                },
                "source": _unit_source(raw_unit),
            })

        # Preserve callsite-level attack-chain observations for the next
        # resolver.  These are deliberately candidate/observed facts: a
        # ledger relation or enhancer data-flow hint does not by itself prove
        # that an external value reaches a dangerous parameter.
        attack_chain = reach.get("attack_chain_context")
        if isinstance(attack_chain, Mapping):
            callsites = attack_chain.get("callsite_contexts")
            if isinstance(callsites, list):
                for index, callsite in enumerate(callsites[:MAX_FACTS_PER_UNIT]):
                    if not isinstance(callsite, Mapping):
                        continue
                    facts.append({
                        "fact_id": f"attack_chain_callsite:{unit_id}:{index}",
                        "kind": "attack_chain_callsite_observation",
                        "status": "candidate",
                        "source_unit_id": unit_id,
                        "target_id": unit_id,
                        "evidence": {
                            "callsite": dict(callsite),
                            "context_status": attack_chain.get("status", "not_evaluated"),
                            "context_complete": attack_chain.get("complete"),
                            "missing_evidence": list(
                                attack_chain.get("missing_evidence", []) or []
                            )[:16],
                        },
                        "source": _unit_source(raw_unit),
                        "admission": "candidate_only_until_parameter_and_flow_validation",
                    })
                    facts_by_kind["attack_chain_callsite_observation"] += 1

    task_rows = _list((gap_tasks or {}).get("tasks")) if isinstance(gap_tasks, Mapping) else []
    pending_tasks = [
        {
            "task_id": row.get("task_id"),
            "site_key": row.get("site_key"),
            "status": row.get("status"),
            "kind": row.get("kind"),
            "caller_id": row.get("caller_id"),
            "candidate_targets": row.get("candidate_targets", []),
            "reason_codes": row.get("reason_codes", []),
        }
        for row in task_rows
        if isinstance(row, Mapping) and row.get("status") == "pending"
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "openharmony_analysis_feedback",
        "repository": repository,
        "provenance": {
            "source_revision": source_revision or "unknown",
            "build_config_id": build_config_id or "unknown",
            "graph_versions": sorted({_text(v) for v in graph_versions if _text(v)}),
            "dataset_metadata": source.get("metadata", {}),
            "results_fingerprint": (results or {}).get("analyze_fingerprint")
            if isinstance(results, Mapping) else None,
        },
        "summary": {
            "units": len([u for u in units if isinstance(u, Mapping)]),
            "units_with_entry_paths": path_units,
            "units_without_entry_paths": unknown_path_units,
            "stage1_observations": sum(stage1_counts.values()),
            "stage1_findings": dict(sorted(stage1_counts.items())),
            "candidate_facts": sum(facts_by_kind.values()),
            "facts_by_kind": dict(sorted(facts_by_kind.items())),
            "pending_gap_tasks": len(pending_tasks),
            "strict_graph_mutated": False,
        },
        "pending_gap_tasks": pending_tasks,
        "facts": facts,
        "limitations": [
            "增强器和 Stage 1 的引用只作为候选/观察事实保存，不自动提升调用边",
            "入口路径是当前有效图上的静态路径，不等同于运行时必然触发或数据流已到达",
            "没有入口路径的单元保留 unknown，不解释为不可达",
        ],
    }


def write_analysis_feedback(
    output_path: str | Path,
    dataset: Mapping[str, Any] | None,
    **kwargs: Any,
) -> dict[str, Any]:
    payload = build_analysis_feedback(dataset, **kwargs)
    write_json(output_path, payload, indent=2)
    return payload


def load_analysis_feedback(path: str | Path) -> dict[str, Any]:
    try:
        payload = read_json(path)
    except (OSError, ValueError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


__all__ = [
    "SCHEMA_VERSION",
    "FEEDBACK_FILENAME",
    "build_analysis_feedback",
    "write_analysis_feedback",
    "load_analysis_feedback",
]
