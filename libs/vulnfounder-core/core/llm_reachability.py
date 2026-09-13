"""
LLM-based reachability review stage.

A complementary, advisory pass over the **full, unfiltered** codebase that
uses a strong LLM (Opus by default) to surface reachability signals beyond
what the structural analysis catches:

- Likely entry points the structural pass missed (framework-specific
  handlers, plugin registrations, lambdas, message handlers, etc.).
- External content ingestion sites (HTTP request bodies, file/network
  reads, env/argv, IPC channels).
- Cross-process or async data flow indicators.

Pipeline ordering (managed by ``core/scanner.py``):

1. Parse with ``processing_level="all"`` so every unit is available.
2. ``analyze_reachability`` reviews all units and returns signals.
3. ``apply_signals`` records semantic signals after admission checks and
   derives strict roots only from high-confidence signals with concrete
   evidence (and inbound direction for ``cross_process``). Medium-confidence
   signals become candidate seeds for a separate BFS over accepted edges; they
   never become strict entry points.
4. The structural reachability filter re-runs with both LLM-promoted entry
   points and high-confidence semantic signals added as extra BFS seeds,
   yielding a dataset filtered to the user's requested ``processing_level``
   but expanded by LLM findings.

Signals are **promote-only** — they never DEMOTE a unit that structural
analysis already kept. This matches the "complements, not replaces" intent
in issue #17.

Output:
- ``analyze_reachability(...)`` returns a list of ``ReachabilitySignal``
  dicts.
- ``apply_signals(dataset, signals)`` mutates the dataset in place so each
  unit gains an ``llm_reachability_signals`` field. Evidence-backed,
  high-confidence ``entry_point`` signals set ``is_entry_point = True``;
  evidence-backed, inbound high-confidence ``external_input`` and
  ``cross_process`` signals set ``semantic_reachability_seed = True`` without
  changing the entry-point flag; medium-confidence signals of every valid kind set
  ``semantic_reachability_candidate_seed = True`` and are retained for a
  candidate frontier; the legacy retain-only markers remain for compatibility.

Usage:
    from core.llm_reachability import analyze_reachability, apply_signals

    signals = analyze_reachability(dataset, app_context=app_ctx)
    apply_signals(dataset, signals)
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from core.platforms.prompt_context import PlatformPromptContext
from core.observability import print_chinese_log
from prompts._fence import collapse_inline

if TYPE_CHECKING:
    from utilities.llm import PhaseBinding


# Maximum number of units to send in a single LLM call. Larger batches save
# round trips but risk token-limit errors and degraded recall.
DEFAULT_BATCH_SIZE = 25

# Default maximum bytes of code we send per unit. Trimmed to keep prompts
# tractable. Callers can override via the ``max_code_bytes`` parameter on
# :func:`analyze_reachability` (exposed as ``--llm-reachability-max-code-bytes``
# on ``vulnfounder scan``); higher values catch entry-point indicators past the
# default cutoff in long handlers / generated code, at proportional cost.
DEFAULT_MAX_CODE_BYTES = 1500
# Backward-compatible alias for any external caller importing the old name.
MAX_CODE_BYTES = DEFAULT_MAX_CODE_BYTES
# Reachability reviews units in batches, so keep the per-unit platform context
# smaller than the shared renderer's general limit to avoid multiplying context
# cost by the batch size.
MAX_PLATFORM_CONTEXT_CHARS = 1_600


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ReachabilitySignal:
    """A single LLM-emitted reachability signal for one unit.

    ``kind`` is one of:
      - ``entry_point`` — unit is itself a likely entry point.
      - ``external_input`` — unit receives external/untrusted input.
      - ``cross_process`` — unit participates in async / cross-process data flow.

    ``confidence`` is one of ``high``, ``medium``, ``low``. ``direction`` is
    used only for ``cross_process``; ``external_input`` is inherently an
    inbound/read signal and does not need a direction value. Evidence fields
    are model-provided audit claims. Strict semantic-seed admission uses high
    confidence plus a non-empty concrete evidence claim; it does not rely on a
    brittle local text matcher. The claim remains model-provided evidence,
    rather than source-level proof.
    """

    unit_id: str
    kind: str
    confidence: str
    reason: str
    boundary: str = "unknown"
    evidence: str = ""
    evidence_excerpt: str = ""
    evidence_line_start: Optional[int] = None
    evidence_line_end: Optional[int] = None
    direction: str = ""
    evidence_status: str = "missing"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        # Direction is meaningful only for cross-process signals.  Keep the
        # internal empty value for compatibility with callers that inspect the
        # dataclass, but do not emit a misleading field for external input or
        # entry-point records in persisted artifacts.
        if self.kind != "cross_process":
            payload.pop("direction", None)
        return payload


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


PROMPT_TEMPLATE = """You are a senior application-security engineer auditing
a codebase for REACHABILITY signals — places where untrusted input can enter
the system. A previous structural pass has already flagged some entry points
and reachable units; your job is to surface ADDITIONAL signals it may have
missed (framework-specific handlers, plugin/CLI registrations, message
queues, async tasks, file/network ingestion, env/argv, IPC, etc.).

Be conservative. Only emit a signal when the code clearly indicates one of:

  - "entry_point"      — this unit is itself a likely entry point reachable
                         by an external actor (HTTP/CLI/queue/stream handler,
                         scheduled task, framework lifecycle hook, etc.).
  - "external_input"   — this unit reads or accepts data from an external
                         source (request body, file, socket, env, argv, stdin,
                         child-process output, untrusted message, etc.). This
                         kind is inherently inbound; do not add a direction.
  - "cross_process"    — this unit dispatches or receives data across async
                         / process / queue boundaries (so taint may flow in
                         or out via a path the static call-graph misses). For
                         this kind, direction MUST be receive, send,
                         bidirectional, or unknown.

Confidence levels:
  - "high"   — the code unambiguously demonstrates the pattern.
  - "medium" — the pattern is present but partially obscured.
  - "low"    — only suggestive; emit only if you'd want a human reviewer.

Return STRICT JSON of the form:

  {{
    "signals": [
      {{"unit_id": "<id>", "kind": "entry_point|external_input|cross_process",
        "confidence": "high|medium|low", "boundary": "binder|socket|hdf_hdi|napi|queue|file|network|unknown",
        "direction": "receive|send|bidirectional|unknown (cross_process only)",
        "evidence": "<short factual claim>",
        "evidence_excerpt": "<source or behavior excerpt, or empty string>",
        "evidence_line_start": <integer or null>,
        "evidence_line_end": <integer or null>,
        "reason": "<one short sentence>"}},
      ...
    ]
  }}

If no signals apply, return ``{{"signals": []}}``. Do NOT wrap the JSON in
markdown fences. Do NOT include any prose outside the JSON.

For ``external_input``, cite the concrete read/receive operation or its
registration context in ``evidence_excerpt``. For ``cross_process``, cite the
operation and state whether this unit receives or sends. Evidence is retained
for audit and explanation. A high-confidence signal without a concrete
evidence claim is not admitted as a strict seed; it is retained as review-only
evidence. This is an evidence-presence check, not a local source-matching or
substring-validation gate.
A function parameter alone is weaker evidence, but may still be reported when
the model's confidence is high. Do not invent line numbers; use null when the
source span is not visible.

{app_context_block}

UNITS TO REVIEW (existing structural flags shown for context — your job is to
ADD signals beyond what those already capture):

{units_block}
"""


def _build_app_context_block(app_context: Optional[Dict[str, Any]]) -> str:
    """Render an optional app-context section for the prompt."""
    if not app_context:
        return "APPLICATION CONTEXT: (none provided)"
    try:
        ctx_json = json.dumps(app_context, indent=2, sort_keys=True)
    except (TypeError, ValueError):
        ctx_json = str(app_context)
    return f"APPLICATION CONTEXT:\n{ctx_json}"


def _trim_code(code: str, max_bytes: int = DEFAULT_MAX_CODE_BYTES) -> str:
    """Truncate a code blob so the batch fits in a reasonable prompt window."""
    if not code:
        return ""
    if len(code) <= max_bytes:
        return code
    return code[:max_bytes] + "\n# ...[truncated]"


def _unit_for_prompt(
    unit: Dict[str, Any],
    max_code_bytes: int = DEFAULT_MAX_CODE_BYTES,
) -> Dict[str, Any]:
    """Project a unit into the minimal shape we send to the LLM."""
    code_blob = ""
    code = unit.get("code") or {}
    if isinstance(code, dict):
        code_blob = code.get("primary_code") or code.get("source") or ""
    elif isinstance(code, str):
        code_blob = code

    projected = {
        "unit_id": unit.get("id", ""),
        "unit_type": unit.get("unit_type", "function"),
        "is_entry_point": bool(unit.get("is_entry_point", False)),
        "reachable": unit.get("reachable"),
        "code": _trim_code(code_blob, max_bytes=max_code_bytes),
    }

    # Source provenance and direct graph neighbors let the model cite an
    # actual boundary operation instead of guessing from a parameter name.
    # These fields are advisory context only; seed admission uses the model's
    # signal kind and confidence, while evidence remains for audit.
    origin = code.get("primary_origin") if isinstance(code, dict) else None
    if isinstance(origin, dict):
        projected["source_path"] = str(origin.get("file_path") or "")
        projected["source_start_line"] = origin.get("start_line")
        projected["source_end_line"] = origin.get("end_line")
    metadata = unit.get("metadata")
    if isinstance(metadata, dict):
        direct_calls = metadata.get("direct_calls")
        direct_callers = metadata.get("direct_callers")
        if isinstance(direct_calls, list):
            projected["direct_calls"] = direct_calls[:32]
        if isinstance(direct_callers, list):
            projected["direct_callers"] = direct_callers[:32]

    raw_platform_context = unit.get("platform_context")
    if raw_platform_context is None:
        raw_platform_context = unit.get("platformContext")
    platform_context = PlatformPromptContext.from_mapping(raw_platform_context)
    if not platform_context.is_openharmony:
        return projected

    raw_language = unit.get("language")
    language = (
        collapse_inline(raw_language)[:32]
        if isinstance(raw_language, str) and raw_language
        else "cpp"
    )
    projected["language"] = language or "cpp"

    rendered_context = platform_context.render_for_phase("reachability")
    if len(rendered_context) > MAX_PLATFORM_CONTEXT_CHARS:
        rendered_context = (
            rendered_context[: MAX_PLATFORM_CONTEXT_CHARS - 1] + "…"
        )
    projected["platform_context"] = rendered_context
    return projected


def build_prompt(
    units: List[Dict[str, Any]],
    app_context: Optional[Dict[str, Any]] = None,
    max_code_bytes: int = DEFAULT_MAX_CODE_BYTES,
) -> str:
    """Assemble the LLM prompt for a batch of units."""
    app_block = _build_app_context_block(app_context)
    payload = [_unit_for_prompt(u, max_code_bytes=max_code_bytes) for u in units]
    units_block = json.dumps(payload, indent=2)
    return PROMPT_TEMPLATE.format(
        app_context_block=app_block,
        units_block=units_block,
    )


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


_VALID_KINDS = {"entry_point", "external_input", "cross_process"}
_VALID_CONFIDENCES = {"high", "medium", "low"}
_VALID_DIRECTIONS = {"receive", "send", "bidirectional", "unknown"}
_VALID_BOUNDARIES = {
    "binder", "socket", "hdf_hdi", "napi", "queue", "file", "network", "unknown"
}
_VALID_EVIDENCE_STATUSES = {"provided", "missing", "local_verified", "model_only"}
_VALID_SEED_STATUSES = {
    "accepted_seed", "reachable_only", "review_only", "rejected"
}


def _short_text(value: Any, limit: int = 2_000) -> str:
    """Coerce a model field to a bounded plain string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:limit]
    # Keep malformed nested values from leaking a large repr into artifacts.
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)[:limit]
    except (TypeError, ValueError):
        return str(value)[:limit]


def _optional_int(value: Any) -> Optional[int]:
    """Return a JSON integer, rejecting bools and arbitrary numeric strings."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Best-effort JSON extraction from a model response.

    Strips common markdown fences and falls back to the first ``{...}``
    block in the text. Returns ``None`` if nothing valid is found.
    """
    if not text:
        return None
    cleaned = text.strip()

    # Strip ```json ... ``` or ``` ... ``` fences.
    fence = re.match(
        r"^```(?:json)?\s*(?P<body>.*?)\s*```\s*$",
        cleaned,
        re.DOTALL | re.IGNORECASE,
    )
    if fence:
        cleaned = fence.group("body").strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Fall back to the first balanced JSON object in the response.
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        snippet = cleaned[start : end + 1]
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            return None
    return None


def parse_response(
    response_text: str,
    valid_unit_ids: Optional[set] = None,
    on_error: Optional[Callable[[str], None]] = None,
) -> List[ReachabilitySignal]:
    """Parse a single LLM response into validated ``ReachabilitySignal``s.

    Malformed entries are skipped (not raised); the optional ``on_error``
    callback receives a one-line description per skipped item, useful for
    logging.
    """
    def _default_log(msg: str) -> None:
        print(f"[LLMReach] {msg}", file=sys.stderr)
        print_chinese_log(
            f"可达性响应校验：{msg}；无效信号会被丢弃，不会污染 dataset。",
            category="可达性决策",
        )

    log = on_error or _default_log

    data = _extract_json(response_text)
    if not isinstance(data, dict):
        log("malformed response: not a JSON object — skipping batch")
        return []

    raw_signals = data.get("signals")
    if not isinstance(raw_signals, list):
        log("malformed response: 'signals' missing or not a list — skipping batch")
        return []

    out: List[ReachabilitySignal] = []
    for idx, item in enumerate(raw_signals):
        if not isinstance(item, dict):
            log(f"signal #{idx}: not an object — skipped")
            continue
        unit_id = item.get("unit_id")
        kind = item.get("kind")
        confidence = item.get("confidence")
        reason = item.get("reason", "")

        if not isinstance(unit_id, str) or not unit_id:
            log(f"signal #{idx}: missing unit_id — skipped")
            continue
        if not isinstance(kind, str) or kind not in _VALID_KINDS:
            log(f"signal #{idx}: invalid kind {kind!r} — skipped")
            continue
        if not isinstance(confidence, str) or confidence not in _VALID_CONFIDENCES:
            log(f"signal #{idx}: invalid confidence {confidence!r} — skipped")
            continue
        if valid_unit_ids is not None and unit_id not in valid_unit_ids:
            log(f"signal #{idx}: unknown unit_id {unit_id!r} — skipped")
            continue

        boundary = item.get("boundary", "unknown")
        if boundary is None:
            boundary = "unknown"
        if not isinstance(boundary, str) or boundary not in _VALID_BOUNDARIES:
            log(f"signal #{idx}: invalid boundary {boundary!r} — skipped")
            continue

        # ``external_input`` is inherently inbound. Direction is meaningful
        # only for ``cross_process``; accepting it on other kinds would make
        # old and new producers disagree about seed semantics.
        direction = item.get("direction", "")
        if kind == "cross_process":
            if direction in (None, ""):
                direction = "unknown"
            if not isinstance(direction, str) or direction not in _VALID_DIRECTIONS:
                log(f"signal #{idx}: invalid direction {direction!r} — skipped")
                continue
        else:
            direction = ""

        evidence = _short_text(item.get("evidence", ""), limit=2_000)
        evidence_excerpt = _short_text(
            item.get("evidence_excerpt", ""), limit=4_000
        )
        evidence_line_start = _optional_int(item.get("evidence_line_start"))
        evidence_line_end = _optional_int(item.get("evidence_line_end"))
        if evidence_line_end is None and evidence_line_start is not None:
            evidence_line_end = evidence_line_start

        out.append(
            ReachabilitySignal(
                unit_id=unit_id,
                kind=kind,
                confidence=confidence,
                reason=_short_text(reason, limit=500),
                boundary=boundary,
                evidence=evidence,
                evidence_excerpt=evidence_excerpt,
                evidence_line_start=evidence_line_start,
                evidence_line_end=evidence_line_end,
                direction=direction,
                # This is an audit-only marker; seed admission depends only on
                # kind and confidence.
                evidence_status=(
                    "provided" if evidence or evidence_excerpt else "missing"
                ),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------


def _chunk(items: List[Any], size: int) -> List[List[Any]]:
    """Split ``items`` into batches of ``size``.

    A non-positive ``size`` is treated as "everything in one batch" so callers
    that disable batching never hit a NameError or empty-output surprise.
    """
    if size <= 0:
        return [list(items)] if items else []
    return [items[i : i + size] for i in range(0, len(items), size)]


def analyze_reachability(
    dataset: Dict[str, Any],
    app_context: Optional[Dict[str, Any]] = None,
    binding: Optional["PhaseBinding"] = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_code_bytes: int = DEFAULT_MAX_CODE_BYTES,
    max_units: Optional[int] = None,
    on_error: Optional[Callable[[str], None]] = None,
) -> List[ReachabilitySignal]:
    """Run the LLM reachability review stage over a parsed dataset.

    Args:
        dataset: Parsed dataset with a ``units`` list, as produced by the
            parser stage. Units are expected to expose ``id``, ``code``, and
            optionally ``is_entry_point`` / ``reachable_from_entry``.
        app_context: Optional application context dict; included in the
            prompt to help the model reason about expected entry points
            (e.g. ``{"application_type": "web_app"}``).
        binding: :class:`PhaseBinding` carrying the adapter+model the
            ``llm_reach`` phase should use. When omitted, a binding is
            resolved from the active config file — useful for ad-hoc
            scripts and tests; pipeline callers should always pass the
            binding their scanner built so any ``--llm-config`` override
            is honored.
        batch_size: Units per LLM call.
        max_code_bytes: Per-unit code-blob truncation limit. Higher values
            give the LLM more context (better recall on long handlers /
            generated code) at proportional Opus cost. Default 1500.
        max_units: Optional cap on how many units to review.
        on_error: Optional callback for parse/validation issues.

    Returns:
        A flat list of :class:`ReachabilitySignal` for every unit the model
        flagged. Unknown unit ids and malformed entries are filtered out.
    """
    units = dataset.get("units") or []
    if max_units is not None and max_units >= 0:
        units = units[:max_units]
    if not units:
        print_chinese_log(
            "可达性复核结束：输入单元为空，没有向模型发送请求，也不会生成虚构信号。",
            category="可达性决策",
        )
        return []

    print_chinese_log(
        f"可达性复核计划：共 {len(units)} 个单元，批大小={batch_size}，"
        f"每单元代码上限={max_code_bytes} 字节；模型只输出入口、外部输入或跨进程信号。",
        category="可达性决策",
    )

    if binding is None:
        # Self-contained fallback for callers that don't have a
        # registry yet (standalone scripts, tests that didn't bother
        # to pass one). Uses the same resolution path the scanner
        # uses, so behavior matches a real scan — including the
        # init-time probe so a misconfigured llm-config fails loud.
        from utilities.llm import (
            build_phase_registry,
            load_config_file,
            probe_registry_or_raise,
            resolve_llm_config,
        )

        cf = load_config_file()
        llm_config = resolve_llm_config(cf, None)
        registry = build_phase_registry(cf, llm_config)
        probe_registry_or_raise(registry)
        binding = registry.get("llm_reach")

    valid_ids = {u.get("id") for u in units if u.get("id")}

    # Lazy import so this module stays usable when callers explicitly
    # provide a binding and never want the registry fallback above.
    from utilities.llm import LLMAuthError, simple_text

    signals: List[ReachabilitySignal] = []
    batches = _chunk(units, batch_size)
    for i, batch in enumerate(batches):
        print_chinese_log(
            f"可达性批次 {i + 1}/{len(batches)}：发送 {len(batch)} 个单元，"
            "提示中保留结构化入口标记作为参考，但要求模型只补充遗漏信号。",
            category="可达性进度",
        )
        prompt = build_prompt(
            batch, app_context=app_context, max_code_bytes=max_code_bytes
        )
        try:
            text = simple_text(binding, prompt, max_tokens=4096)
        except LLMAuthError:
            # Auth failures are fatal and recur on every batch — surface
            # them instead of burying them as a per-batch "failed" line,
            # so the caller can stop and tell the user the key is bad.
            raise
        except Exception as exc:  # noqa: BLE001 — advisory stage; never crash pipeline
            msg = f"batch {i + 1}/{len(batches)} failed: {exc}"
            if on_error:
                on_error(msg)
            else:
                print(f"[LLMReach] {msg}", file=sys.stderr)
                print_chinese_log(
                    f"可达性批次失败：{msg}；跳过该批次并继续处理其它批次。",
                    category="可达性决策",
                )
            continue

        parsed = parse_response(
            text, valid_unit_ids=valid_ids, on_error=on_error
        )
        signals.extend(parsed)
        print_chinese_log(
            f"可达性批次完成：模型返回 {len(parsed)} 条通过校验的信号，"
            f"累计 {len(signals)} 条；未知 unit_id、错误类型和低质量结构已过滤。",
            category="可达性进度",
        )

    print_chinese_log(
        f"可达性复核完成：共得到 {len(signals)} 条有效信号，"
        "下一步由扫描编排器决定是否提升入口并重新执行结构 BFS。",
        category="可达性结果",
    )
    return signals


# ---------------------------------------------------------------------------
# Signal application (promote-only)
# ---------------------------------------------------------------------------


# Confidences at or above this threshold promote ``entry_point`` signals to
# ``is_entry_point = True`` on the target unit.
_PROMOTE_ENTRY_POINT_AT = {"high"}


def _evidence_status_for_signal(signal: ReachabilitySignal) -> str:
    """Classify whether the model supplied any evidence for audit display.

    This deliberately does not inspect repository source.  Evidence status is
    an admission/audit field supplied by the model; source-reference and
    relation validation happen later in call-graph recovery/projection.
    """
    return "provided" if signal.evidence or signal.evidence_excerpt else "missing"


def evaluate_seed_eligibility(
    unit: Dict[str, Any], signal: ReachabilitySignal
) -> Dict[str, str]:
    """Decide how a semantic signal participates in reachability.

    A strict semantic seed requires a known unit, a supported signal kind,
    ``high`` confidence, and a non-empty model evidence claim. For
    ``cross_process`` it additionally requires an inbound direction
    (``receive`` or ``bidirectional``), so a process-originating ``send`` is
    not mistaken for an external entry. This is deliberately an
    evidence-presence check rather than a brittle local substring matcher;
    source-reference and relation-quality validation belongs to call-graph
    projection. Medium-confidence signals are admitted as
    ``reachable_only`` candidate seeds, including ``entry_point``. High/low
    signals that fail the strict evidence gate remain attached as
    ``review_only`` evidence.
    """
    if not isinstance(unit, dict) or unit.get("id") != signal.unit_id:
        return {
            "status": "rejected",
            "reason": "signal unit identity does not match a known dataset unit",
        }
    evidence_status = _evidence_status_for_signal(signal)
    signal.evidence_status = evidence_status
    if signal.kind not in {"entry_point", "external_input", "cross_process"}:
        return {"status": "review_only", "reason": "not a semantic input signal"}
    if signal.confidence == "medium":
        return {
            "status": "reachable_only",
            "reason": (
                "medium-confidence semantic signal admitted as a candidate BFS seed; "
                "not a strict entry point"
            ),
        }
    if signal.confidence not in _PROMOTE_ENTRY_POINT_AT:
        return {
            "status": "review_only",
            "reason": "confidence is below the high-confidence seed threshold",
        }
    if not (signal.evidence or signal.evidence_excerpt):
        return {
            "status": "review_only",
            "reason": "high-confidence signal has no concrete evidence claim",
        }
    if signal.kind == "cross_process" and signal.direction not in {
        "receive",
        "bidirectional",
    }:
        return {
            "status": "review_only",
            "reason": "cross-process signal is not confirmed as inbound",
        }
    if signal.kind == "entry_point":
        return {
            "status": "accepted_entry_seed",
            "reason": "high-confidence entry signal with concrete evidence",
        }
    return {
        "status": "accepted_seed",
        "reason": "high-confidence semantic signal with concrete evidence",
    }


def _signal_identity(signal: ReachabilitySignal) -> tuple:
    """Build a stable identity for duplicate model emissions."""
    direction = signal.direction if signal.kind == "cross_process" else ""
    return (signal.unit_id, signal.kind, signal.boundary, direction)


def _confidence_rank(value: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(value, -1)


def _signal_quality(signal: ReachabilitySignal) -> tuple:
    """Rank duplicate signals without deciding their semantic truth.

    Confidence remains the primary rank.  For equal confidence, retain the
    emission that carries a concrete excerpt/evidence and a known boundary or
    direction; otherwise a first, evidence-free duplicate could hide a later
    usable signal from the same model batch.
    """
    return (
        _confidence_rank(signal.confidence),
        bool(signal.evidence_excerpt),
        bool(signal.evidence),
        signal.boundary != "unknown",
        signal.direction not in {"", "unknown"},
        len(signal.evidence_excerpt or ""),
    )


def _deduplicate_signals(
    signals: List[ReachabilitySignal],
) -> tuple[List[ReachabilitySignal], int]:
    """Deduplicate repeated per-unit signals, retaining the strongest one."""
    best: Dict[tuple, ReachabilitySignal] = {}
    order: List[tuple] = []
    for signal in signals:
        key = _signal_identity(signal)
        current = best.get(key)
        if current is None:
            best[key] = signal
            order.append(key)
            continue
        if _signal_quality(signal) > _signal_quality(current):
            best[key] = signal
    deduplicated = [best[key] for key in order]
    return deduplicated, len(signals) - len(deduplicated)


def apply_signals(
    dataset: Dict[str, Any],
    signals: List[ReachabilitySignal],
) -> Dict[str, Any]:
    """Merge LLM signals back into ``dataset`` (in place, promote-only).

    For each unit referenced by a signal:
      - The signal is appended to a per-unit ``llm_reachability_signals`` list.
      - If the signal kind is ``entry_point`` and it passes the evidence
        admission gate, the unit's ``is_entry_point`` field is set to ``True``
        (never set back to ``False``).
      - A high-confidence ``external_input`` or inbound ``cross_process``
        signal with a concrete evidence claim is marked as a strict semantic
        BFS seed. Evidence presence is required, but brittle local text
        matching is not performed here.
      - A medium-confidence signal marks its target as a candidate seed and
        retains the legacy ``reachability_retain_only`` markers. The filter
        may propagate from this target over accepted edges, but the result is
        explicitly ``candidate_reachable`` rather than strict reachable.

    Crucially, this never DEMOTES a unit. ``is_entry_point=True`` set by the
    structural pass remains true regardless of what the LLM said.

    Returns a small summary dict::

        {
            "signals_received": <n>,
            "signals_applied": <n>,
            "entry_points_promoted": <n>,
            "semantic_seed_ids": [...],
            "semantic_candidate_seed_ids": [...],
            "semantic_retain_only_ids": [...],
            "reachable_only_ids": [...],
            "seed_counts": {...},
            "retained_only_counts": {...},
            "rejected_counts": {...},
            "review_only": <n>,
            "retained_only": <n>,
            "duplicates_removed": <n>,
            "units_touched": <n>,
        }
    """
    units = dataset.get("units") or []
    by_id = {u.get("id"): u for u in units if u.get("id")}

    normalized_signals, duplicates_removed = _deduplicate_signals(signals)
    promoted = 0
    touched: set = set()
    semantic_seed_ids: set[str] = set()
    semantic_candidate_seed_ids: set[str] = set()
    semantic_retain_only_ids: set[str] = set()
    reachable_only_ids: set[str] = set()
    seed_counts = {
        "entry_point": 0,
        "external_input": 0,
        # ``cross_process`` is the total number of accepted semantic seeds.
        # Keep the receive subset separately for compatibility with older
        # reports and UI consumers.
        "cross_process": 0,
        "cross_process_receive": 0,
    }
    retained_only_counts = {
        "entry_point": 0,
        "external_input": 0,
        "cross_process": 0,
    }
    rejected_counts: Dict[str, int] = {}
    review_only = 0
    retained_only = 0
    applied = 0

    for sig in normalized_signals:
        unit = by_id.get(sig.unit_id)
        if unit is None:
            continue

        decision = None
        if sig.kind in {"entry_point", "external_input", "cross_process"}:
            decision = evaluate_seed_eligibility(unit, sig)
            sig.evidence_status = _evidence_status_for_signal(sig)

        existing = unit.setdefault("llm_reachability_signals", [])
        record = sig.to_dict()
        if decision is not None:
            record["seed_status"] = decision["status"]
            record["seed_reason"] = decision["reason"]
        existing.append(record)
        applied += 1
        touched.add(sig.unit_id)

        if (
            sig.kind == "entry_point"
            and decision is not None
            and decision.get("status") == "accepted_entry_seed"
            and not unit.get("is_entry_point", False)
        ):
            unit["is_entry_point"] = True
            unit["entry_point_reason"] = f"llm_reachability: {sig.reason}"
            promoted += 1

        if (
            sig.kind == "entry_point"
            and decision is not None
            and decision.get("status") == "accepted_entry_seed"
        ):
            seed_counts["entry_point"] += 1

        if decision is not None:
            status = decision["status"]
            if status == "accepted_seed":
                semantic_seed_ids.add(sig.unit_id)
                if sig.kind == "external_input":
                    seed_counts["external_input"] += 1
                    source = "llm_external_input"
                else:
                    seed_counts["cross_process"] += 1
                    if sig.direction in {"receive", "bidirectional"}:
                        seed_counts["cross_process_receive"] += 1
                        source = "llm_cross_process_inbound"
                    else:
                        source = "llm_cross_process"
                unit["semantic_reachability_seed"] = True
                sources = unit.setdefault("reachability_seed_source", [])
                if isinstance(sources, str):
                    sources = [sources]
                    unit["reachability_seed_source"] = sources
                if not isinstance(sources, list):
                    sources = []
                    unit["reachability_seed_source"] = sources
                if source not in sources:
                    sources.append(source)
                reasons = unit.setdefault("semantic_seed_reasons", [])
                if isinstance(reasons, str):
                    reasons = [reasons]
                    unit["semantic_seed_reasons"] = reasons
                if not isinstance(reasons, list):
                    reasons = []
                    unit["semantic_seed_reasons"] = reasons
                reason = decision["reason"]
                if reason not in reasons:
                    reasons.append(reason)
            elif status == "accepted_entry_seed":
                # LLM entry-point signals use the ordinary structural BFS root
                # once the semantic evidence gate has passed.  Keep this
                # status separate from input seeds so reports can distinguish
                # the two admission paths.
                pass
            elif status == "review_only":
                review_only += 1
                rejected_counts["review_only"] = rejected_counts.get("review_only", 0) + 1
            elif status == "reachable_only":
                retained_only += 1
                reachable_only_ids.add(sig.unit_id)
                semantic_candidate_seed_ids.add(sig.unit_id)
                if sig.kind in {"external_input", "cross_process"}:
                    semantic_retain_only_ids.add(sig.unit_id)
                retained_only_counts[sig.kind] += 1
                unit["reachability_retain_only"] = True
                unit["semantic_reachability_candidate_seed"] = True
                if sig.kind in {"external_input", "cross_process"}:
                    unit["semantic_reachability_retain_only"] = True
                if sig.kind == "entry_point":
                    source = "llm_entry_point_retain_only"
                elif sig.kind == "external_input":
                    source = "llm_external_input_retain_only"
                elif sig.direction in {"receive", "bidirectional"}:
                    source = "llm_cross_process_inbound_retain_only"
                else:
                    source = "llm_cross_process_retain_only"
                sources = unit.setdefault("reachability_retain_only_source", [])
                if isinstance(sources, str):
                    sources = [sources]
                    unit["reachability_retain_only_source"] = sources
                if not isinstance(sources, list):
                    sources = []
                    unit["reachability_retain_only_source"] = sources
                if source not in sources:
                    sources.append(source)
                reasons = unit.setdefault("semantic_retain_only_reasons", [])
                if isinstance(reasons, str):
                    reasons = [reasons]
                    unit["semantic_retain_only_reasons"] = reasons
                if not isinstance(reasons, list):
                    reasons = []
                    unit["semantic_retain_only_reasons"] = reasons
                reason = decision["reason"]
                if reason not in reasons:
                    reasons.append(reason)
            else:
                rejected_counts[status] = rejected_counts.get(status, 0) + 1

    return {
        "signals_received": len(signals),
        "signals_applied": applied,
        "entry_points_promoted": promoted,
        "units_touched": len(touched),
        "semantic_seed_ids": sorted(semantic_seed_ids),
        "semantic_candidate_seed_ids": sorted(semantic_candidate_seed_ids),
        "semantic_candidate_seed_count": len(semantic_candidate_seed_ids),
        "semantic_retain_only_ids": sorted(semantic_retain_only_ids),
        "reachable_only_ids": sorted(reachable_only_ids),
        "seed_counts": seed_counts,
        "retained_only_counts": retained_only_counts,
        "rejected_counts": rejected_counts,
        "review_only": review_only,
        "retained_only": retained_only,
        "duplicates_removed": duplicates_removed,
    }


def signals_to_json(signals: List[ReachabilitySignal]) -> List[Dict[str, Any]]:
    """Serialize a list of signals for JSON persistence."""
    return [s.to_dict() for s in signals]
