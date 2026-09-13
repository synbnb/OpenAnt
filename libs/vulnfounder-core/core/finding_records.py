"""Bounded, backward-compatible records for multiple issues per unit.

Stage 1 historically returned one top-level ``finding``.  That field remains
the primary target verdict, while this module normalizes an additive
``findings`` list so a model can preserve independent target and context risks
without changing the existing scanner/report contract.

The input is model supplied.  The normalizer therefore deliberately keeps a
small allow-list, bounds strings/lists, and never lets a secondary context risk
silently replace the target verdict.
"""

from __future__ import annotations

import hashlib
from typing import Any


VALID_FINDINGS = {"safe", "protected", "bypassable", "vulnerable", "inconclusive"}
VALID_SCOPES = {"target", "context"}
VALID_RELATIONS = {"primary", "secondary", "context_risk", "related"}
MAX_FINDINGS = 16
MAX_TEXT = 8_000
MAX_ID = 256
MAX_LIST_ITEMS = 24
MAX_LIST_TEXT = 2_000

_SCALAR_FIELDS = (
    "finding_id",
    "scope",
    "relation",
    "target_match",
    "function_analyzed",
    "file",
    "line_start",
    "line_end",
    "reasoning",
    "attack_scenario",
    "dataflow_summary",
    "guard_analysis",
    "confidence",
    "cwe_id",
    "cwe_name",
)
_LIST_FIELDS = (
    "vulnerability_categories",
    "impact",
    "evidence",
    "counterevidence",
    "missing_evidence",
)


def _text(value: Any, limit: int = MAX_TEXT) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()[:limit]
    return None


def _bounded_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    return [
        item.strip()[:MAX_LIST_TEXT]
        for item in value[:MAX_LIST_ITEMS]
        if isinstance(item, str) and item.strip()
    ]


def _bool_or_none(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1"}:
            return True
        if normalized in {"false", "no", "0"}:
            return False
    return None


def _stable_id(record: dict) -> str:
    basis = "|".join(
        str(record.get(key, ""))
        for key in ("scope", "function_analyzed", "file", "line_start", "line_end", "finding")
    )
    basis += "|" + ",".join(record.get("vulnerability_categories", []))
    digest = hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:20]
    return f"finding-{digest}"


def normalize_findings(
    raw: Any,
    *,
    primary_finding: str | None = None,
    default_scope: str = "target",
    synthesize_primary: bool = False,
) -> list[dict]:
    """Return bounded independent finding records from model supplied data.

    ``synthesize_primary`` is used for legacy one-finding responses.  It makes
    the additive list available to new consumers while leaving the historical
    top-level fields untouched.
    """
    records: list[dict] = []
    if isinstance(raw, (list, tuple)):
        candidates = raw[:MAX_FINDINGS]
    else:
        candidates = []

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        value = candidate.get("finding") or candidate.get("verdict")
        if not isinstance(value, str):
            continue
        finding = value.strip().lower()
        if finding not in VALID_FINDINGS:
            continue

        scope = candidate.get("scope", default_scope)
        scope = scope.strip().lower() if isinstance(scope, str) else default_scope
        if scope not in VALID_SCOPES:
            scope = default_scope if default_scope in VALID_SCOPES else "target"

        relation = candidate.get("relation")
        relation = relation.strip().lower() if isinstance(relation, str) else ""
        if relation not in VALID_RELATIONS:
            relation = "primary" if scope == "target" and not records else (
                "context_risk" if scope == "context" else "secondary"
            )

        record: dict[str, Any] = {
            "finding": finding,
            "scope": scope,
            "relation": relation,
        }
        target_match = _bool_or_none(candidate.get("target_match"))
        if target_match is not None:
            record["target_match"] = target_match
        elif scope == "target":
            record["target_match"] = True
        else:
            record["target_match"] = False

        for key in _SCALAR_FIELDS:
            if key in {"finding_id", "scope", "relation", "target_match"}:
                continue
            value = candidate.get(key)
            if key in {"function_analyzed", "file", "reasoning", "attack_scenario", "dataflow_summary", "guard_analysis", "cwe_name"}:
                value = _text(value)
            elif key in {"line_start", "line_end", "cwe_id"}:
                value = value if isinstance(value, int) and not isinstance(value, bool) else None
            elif key == "confidence":
                value = value if isinstance(value, (int, float)) and not isinstance(value, bool) else None
                if value is not None:
                    value = max(0.0, min(1.0, float(value)))
            if value not in (None, ""):
                record[key] = value

        for key in _LIST_FIELDS:
            values = _bounded_list(candidate.get(key))
            if values:
                record[key] = values

        supplied_id = _text(candidate.get("finding_id"), MAX_ID)
        record["finding_id"] = supplied_id or _stable_id(record)
        records.append(record)

    if not records and synthesize_primary:
        finding = str(primary_finding or "inconclusive").strip().lower()
        if finding not in VALID_FINDINGS:
            finding = "inconclusive"
        record = {
            "finding": finding,
            "scope": "target",
            "relation": "primary",
            "target_match": True,
        }
        record["finding_id"] = _stable_id(record)
        records.append(record)
    return records


def ensure_primary_record(
    records: list[dict],
    primary_finding: str | None,
) -> list[dict]:
    """Ensure a legacy target verdict has a corresponding target record.

    A model may correctly report a neighboring ``scope=context`` issue while
    omitting the target item from the new inventory.  The historical
    top-level verdict is still the target verdict in that case, so append a
    minimal synthetic primary record instead of allowing the context item to
    become the only record.  Existing records are returned unchanged.
    """
    if not isinstance(records, list):
        records = []
    normalized = str(primary_finding or "").strip().lower()
    if normalized not in VALID_FINDINGS:
        return records
    for record in records:
        if (
            isinstance(record, dict)
            and record.get("scope") == "target"
            and record.get("finding") == normalized
            and record.get("target_match") is not False
        ):
            return records
    synthetic = {
        "finding": normalized,
        "scope": "target",
        "relation": "primary",
        "target_match": True,
    }
    synthetic["finding_id"] = _stable_id(synthetic)
    records.append(synthetic)
    return records


def primary_record(records: list[dict], primary_finding: str | None = None) -> dict | None:
    """Select a target primary record without promoting context findings."""
    target_records = [
        record for record in records
        if record.get("scope") == "target" and record.get("target_match") is not False
    ]
    if primary_finding:
        normalized = primary_finding.strip().lower()
        for record in target_records:
            if record.get("finding") == normalized and record.get("relation") == "primary":
                return record
    return next(
        (record for record in target_records if record.get("relation") == "primary"),
        target_records[0] if target_records else None,
    )
