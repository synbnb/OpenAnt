"""OpenHarmony 调用图缺口任务队列（P3 第一批）。

P0/P1/P2 会不断产生调用点台账、有效图和候选事实。这个模块把这些事实
转换成按调用点去重的、可增量处理的任务队列，而不是继续把候选记录数当成
缺口数量。任务队列是诊断/调度产物：它不会把未经核验的候选边提升为 strict
调用边，也不会改变原生 ``call_graph.json``。
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from utilities.file_io import read_json, write_json


SCHEMA_VERSION = 1
TASK_FILENAME = "call_graph_gap_tasks.json"


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple, set)) else []


def _reasons(site: Mapping[str, Any]) -> list[str]:
    values = site.get("reason_codes", [])
    if not isinstance(values, list):
        return []
    return sorted({_text(item) for item in values if _text(item)})


def _task_kind(site: Mapping[str, Any]) -> str:
    """Choose the next evidence task from source evidence, not function names."""
    expression = _text(site.get("expression")).lower()
    reasons = set(_reasons(site))
    if "callback" in expression or "lambda" in expression or "handler" in expression:
        return "callback_or_dispatch_binding"
    if "function" in expression or "(*" in expression or "->" in expression:
        return "function_pointer_or_virtual_binding"
    if "factory" in expression or "create" in expression:
        return "factory_object_flow"
    if "parse_context_incomplete" in reasons or "build_context_unknown_or_non_product" in reasons:
        return "semantic_compile_context"
    if "binding_incomplete" in reasons:
        return "direct_symbol_binding"
    if not site.get("candidate_targets"):
        return "unresolved_call_site"
    return "candidate_relation_review"


def _priority(site: Mapping[str, Any]) -> int:
    """Score work so a real unresolved edge is handled before audit-only sites."""
    score = 10
    if bool(site.get("ledger_unrepaired")):
        score += 60
    if not site.get("candidate_targets"):
        score += 25
    reasons = set(_reasons(site))
    score += 15 if "binding_incomplete" in reasons else 0
    score += 10 if "parse_context_incomplete" in reasons else 0
    score += 10 if "build_context_unknown_or_non_product" in reasons else 0
    return score


def _next_actions(kind: str, site: Mapping[str, Any]) -> list[str]:
    actions = {
        "direct_symbol_binding": [
            "确认调用表达式、接收者类型、参数签名和声明/定义位置",
            "若绑定在当前配置下完整，写入可验证语义事实",
        ],
        "semantic_compile_context": [
            "定位匹配源码版本的构建参数、头文件和生成文件",
            "在记录配置来源后重放语义解析，区分手工候选与产品配置",
        ],
        "function_pointer_or_virtual_binding": [
            "追踪函数指针/虚对象的赋值、工厂返回和注册关系",
            "保存可能目标集合及集合完整性，不把单一观察目标当作唯一目标",
        ],
        "factory_object_flow": [
            "追踪工厂分支、对象类型和返回值到实际接口调用站点",
            "将值流事实与真正的执行调用边分开记录",
        ],
        "callback_or_dispatch_binding": [
            "定位注册点、事件/命令选择条件和实际触发实现",
            "确认异步或跨线程边界，并保留触发前提",
        ],
        "unresolved_call_site": [
            "读取调用表达式上下文和接收者声明",
            "搜索定义、注册关系和构建条件，必要时交给 LLM 提出候选事实",
        ],
        "candidate_relation_review": [
            "复核候选目标的类型/签名兼容性和源码证据",
            "候选集合完整时才允许升级为 strict，否则保持 candidate",
        ],
    }
    return actions.get(kind, actions["candidate_relation_review"])


def build_gap_tasks(
    gap_report: Mapping[str, Any] | None,
    *,
    repository: str | None = None,
    source_revision: str | None = None,
    build_config_id: str | None = None,
    graph_versions: Iterable[str] = (),
) -> dict[str, Any]:
    """Build a stable task queue from a P1 gap report.

    Only sites with ``ledger_edge_missing`` are scheduling targets. Candidate-
    only groups remain in the original gap report and do not inflate the task
    count. A repaired site is marked ``resolved`` but retained for audit.
    """
    report = gap_report if isinstance(gap_report, Mapping) else {}
    grouped: dict[str, dict[str, Any]] = {}
    kind_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    for raw in report.get("sites", []) if isinstance(report.get("sites"), list) else []:
        if not isinstance(raw, Mapping) or not bool(raw.get("ledger_edge_missing")):
            continue
        site = dict(raw)
        site_key = _text(site.get("site_key")) or _text(site.get("site_id"))
        if not site_key:
            continue
        kind = _task_kind(site)
        status = "resolved" if not bool(site.get("ledger_unrepaired")) else "pending"
        task = {
            "task_id": f"gap:{site_key}",
            "site_key": site_key,
            "site_id": site.get("site_id"),
            "status": status,
            "priority": _priority(site),
            "kind": kind,
            "caller_id": site.get("caller_id"),
            "file": site.get("file"),
            "line_start": site.get("line_start"),
            "line_end": site.get("line_end"),
            "expression": site.get("expression"),
            "candidate_targets": list(site.get("candidate_targets", []) or []),
            "candidate_completeness": list(site.get("candidate_completeness", []) or []),
            "reason_codes": _reasons(site),
            "next_actions": _next_actions(kind, site),
            "evidence": {
                "ledger_edge_missing": True,
                "ledger_unrepaired": bool(site.get("ledger_unrepaired")),
                "candidate_record_count": site.get("candidate_record_count", 0),
                "candidate_target_count": site.get("candidate_target_count", 0),
                "resolvers": list(site.get("resolvers", []) or []),
                "source_kinds": list(site.get("source_kinds", []) or []),
            },
            "assumptions": [
                "任务状态只描述当前有效图快照，不代表运行时必然执行",
                "candidate 目标需要独立绑定和配置核验后才能进入 strict 图",
            ],
        }
        existing = grouped.get(site_key)
        if existing is None:
            grouped[site_key] = task
        else:
            # Be tolerant of reports assembled from several candidate sources:
            # one source site must still produce exactly one scheduling task.
            existing["candidate_targets"] = sorted({
                *existing.get("candidate_targets", []),
                *task.get("candidate_targets", []),
            })
            existing["reason_codes"] = sorted({
                *existing.get("reason_codes", []),
                *task.get("reason_codes", []),
            })
            existing["priority"] = max(existing["priority"], task["priority"])
            existing["evidence"]["candidate_record_count"] = max(
                int(existing["evidence"].get("candidate_record_count", 0) or 0),
                int(task["evidence"].get("candidate_record_count", 0) or 0),
            )
            if status == "pending":
                existing["status"] = "pending"
            existing["next_actions"] = sorted({
                *existing.get("next_actions", []),
                *task.get("next_actions", []),
            })

    tasks = list(grouped.values())
    for task in tasks:
        kind_counts[str(task.get("kind"))] += 1
        status_counts[str(task.get("status"))] += 1

    tasks.sort(key=lambda item: (-int(item["priority"]), item["task_id"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "openharmony_call_graph_gap_tasks",
        "repository": repository,
        "provenance": {
            "source_revision": source_revision or "unknown",
            "build_config_id": build_config_id or "unknown",
            "graph_versions": sorted({_text(v) for v in graph_versions if _text(v)}),
            "source_gap_report": "call_graph_gap_report.json",
        },
        "summary": {
            "tasks": len(tasks),
            "pending": status_counts.get("pending", 0),
            "resolved": status_counts.get("resolved", 0),
            "by_kind": dict(sorted(kind_counts.items())),
            "priority_max": max((int(t["priority"]) for t in tasks), default=0),
        },
        "tasks": tasks,
    }


def write_gap_tasks(
    output_path: str | Path,
    gap_report: Mapping[str, Any] | None,
    *,
    repository: str | None = None,
    source_revision: str | None = None,
    build_config_id: str | None = None,
    graph_versions: Iterable[str] = (),
) -> dict[str, Any]:
    payload = build_gap_tasks(
        gap_report,
        repository=repository,
        source_revision=source_revision,
        build_config_id=build_config_id,
        graph_versions=graph_versions,
    )
    write_json(output_path, payload, indent=2)
    return payload


def load_gap_tasks(path: str | Path) -> dict[str, Any]:
    try:
        payload = read_json(path)
    except (OSError, ValueError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


__all__ = [
    "SCHEMA_VERSION",
    "TASK_FILENAME",
    "build_gap_tasks",
    "write_gap_tasks",
    "load_gap_tasks",
]
