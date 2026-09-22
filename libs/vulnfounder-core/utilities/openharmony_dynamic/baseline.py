"""阶段 0：动态样本基线与 clean-room 输入边界。

该模块只做样本标准化和审计快照，不访问设备、不加载历史 exemplar，也不把
候选攻击链直接放入模型上下文。它允许批量运行器在真正的协议恢复前记录：
样本身份、源码快照、漏洞类别、当前阻断原因和本轮允许提供给模型的来源。
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Iterable

from .finding_input import FindingInput


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _source_snapshot(finding: FindingInput) -> list[dict[str, Any]]:
    root = Path(finding.repo_root).resolve() if finding.repo_root else None
    items: list[dict[str, Any]] = []
    for raw in finding.source_paths:
        display = str(raw)
        path = Path(display)
        if not path.is_absolute() and root is not None:
            path = root / path
        item: dict[str, Any] = {"path": display, "exists": path.is_file()}
        if path.is_file():
            try:
                item["bytes"] = path.stat().st_size
            except OSError:
                item["bytes"] = None
            item["sha256"] = _sha256_file(path)
        items.append(item)
    return items


def baseline_item(finding: FindingInput, *, clean_room: bool = True) -> dict[str, Any]:
    """生成一个不泄露历史答案的样本基线条目。"""
    context = finding.analysis_context if isinstance(finding.analysis_context, dict) else {}
    unresolved = context.get("unresolved_questions", context.get("missing_evidence", []))
    if isinstance(unresolved, str):
        unresolved = [unresolved]
    if not isinstance(unresolved, list):
        unresolved = []
    model_sources = ["current_finding", "current_source_evidence"]
    if not clean_room:
        model_sources.extend(["device_facts", "exemplar"])
    # candidate_attack_chains 只保留在审计侧摘要中；model_context 不携带它，
    # 防止“阶段 0 基线”绕过 clean-room 约束把答案链传给协议 Agent。
    return {
        "sample_id": finding.finding_id,
        "unit_id": finding.unit_id,
        "vuln_class": finding.vuln_class,
        "target_function": finding.sink or finding.description,
        "source_revision": str(context.get("source_revision", "")),
        "reference_revision": str(context.get("reference_revision", "")),
        "repository": finding.repo_root,
        "source_snapshot": _source_snapshot(finding),
        "candidate_entry_count": len(finding.entry_hints),
        "candidate_route_count": len(finding.candidate_attack_chains),
        "unresolved_questions": [str(item) for item in unresolved if str(item).strip()],
        "model_context": {
            "mode": "clean_room" if clean_room else "assisted",
            "allowed_sources": model_sources,
            "forbidden_sources": [] if not clean_room else ["historical_exemplar", "historical_payload", "answer_key"],
        },
        "audit_only": {
            "entry_hints": list(finding.entry_hints),
            "candidate_attack_chains_present": bool(finding.candidate_attack_chains),
        },
    }


def build_baseline(findings: Iterable[FindingInput], *, clean_room: bool = True) -> dict[str, Any]:
    """批量生成阶段 0 基线；重复 sample_id 会被拒绝而不是静默覆盖。"""
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.finding_id in seen:
            raise ValueError(f"重复 sample_id: {finding.finding_id}")
        seen.add(finding.finding_id)
        items.append(baseline_item(finding, clean_room=clean_room))
    return {
        "schema_version": "vf.dynamic.baseline.v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "clean_room": clean_room,
        "sample_count": len(items),
        "items": items,
    }


def write_baseline(
    findings: Iterable[FindingInput],
    path: str | Path,
    *,
    clean_room: bool = True,
) -> dict[str, Any]:
    payload = build_baseline(findings, clean_room=clean_room)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(out)
    return payload
