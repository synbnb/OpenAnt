"""Stage 1 analysis primitives.

These three functions were defined in ``experiment.py`` — a research harness that
is NOT a packaged module — and imported from there by ``core/analyzer.py``. That
made the installed product unimportable: `pip install vulnfounder` ships the seven
packages listed in pyproject, `experiment.py` is a loose top-level file, and
``import core.analyzer`` raised ModuleNotFoundError in any clean environment.
Verified by building a wheel and installing it into an empty venv.

The dependency also ran the wrong way round: production reaching into research
code. It now runs research -> product; ``experiment.py`` imports these from here.

Nothing else moved. These were chosen because they are exactly what ``core`` used
and they depend only on stdlib and shipped packages (utilities/, prompts/).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from datetime import datetime

from prompts.prompt_selector import get_analysis_prompt
from prompts.vulnerability_analysis import get_system_prompt as get_stage1_system_prompt
from utilities.context_reviewer import ContextReviewer
from utilities.json_corrector import JSONCorrector
from utilities.llm import PhaseBinding, simple_text
from core.file_boundary import split_on_boundary
from core.attack_chain_context import (
    context_from_unit,
    normalize_attack_chain_context,
    stage_context_from_unit,
)
from core.finding_records import (
    VALID_FINDINGS,
    ensure_primary_record,
    normalize_findings,
    primary_record,
)

if TYPE_CHECKING:  # avoids a runtime cycle: context/ imports utilities/ which
    # imports prompts/ which imports core/. The annotation is a string either way.
    from context.application_context import ApplicationContext

def _normalize_result(result: dict) -> dict:
    """Normalize LLM response fields to canonical names.

    Handles cases where the model returns 'finding' instead of 'verdict',
    or uses different casing/naming conventions.
    """
    # Normalize finding -> verdict
    if "verdict" not in result and "finding" in result:
        finding = result["finding"]
        if not isinstance(finding, str):
            # A non-string finding (list/dict/null/number) is a malformed model reply,
            # not a verdict — map it to ERROR so the error / manual-review accounting
            # counts it, instead of a garbage verdict (e.g. "['VULNERABLE']" from
            # str(finding).upper()) that silently escapes that accounting.
            result["verdict"] = "ERROR"
        else:
            finding_to_verdict = {
                "vulnerable": "VULNERABLE",
                "safe": "SAFE",
                "protected": "PROTECTED",
                "bypassable": "BYPASSABLE",
                "inconclusive": "INCONCLUSIVE",
                "insufficient_context": "INSUFFICIENT_CONTEXT",
            }
            result["verdict"] = finding_to_verdict.get(finding.lower(), finding.upper())

    # Ensure verdict is uppercase
    if "verdict" in result and isinstance(result["verdict"], str):
        result["verdict"] = result["verdict"].upper()

    # Ensure CWE fields are always present.
    if "cwe_id" not in result:
        result["cwe_id"] = 0
    if "cwe_name" not in result:
        result["cwe_name"] = None

    # Preserve an additive inventory of independent issues.  The historical
    # top-level ``finding`` remains the target/primary verdict; a context risk
    # must never silently replace it.  Legacy one-finding responses receive a
    # synthesized primary record so downstream consumers can adopt the new
    # collection incrementally.
    primary_finding = result.get("finding")
    if not isinstance(primary_finding, str):
        primary_finding = result.get("verdict")
    records = normalize_findings(
        result.get("findings"),
        primary_finding=primary_finding,
        synthesize_primary=(
            isinstance(primary_finding, str)
            and primary_finding.strip().lower() in VALID_FINDINGS
        ),
    )
    records = ensure_primary_record(records, primary_finding)
    if records:
        result["findings"] = records
        primary = primary_record(records, primary_finding)
        if primary:
            if str(result.get("finding", "")).strip().lower() not in VALID_FINDINGS:
                result["finding"] = primary["finding"]
                result["verdict"] = primary["finding"].upper()
            result["primary_finding_id"] = primary["finding_id"]
            result["finding_scope"] = primary.get("scope", "target")

    return result


def _unit_language(unit: dict) -> str:
    """Return a normalized unit language while preserving legacy fallback."""
    language = unit.get("language")
    if not isinstance(language, str) or not language.strip():
        metadata = unit.get("metadata")
        if isinstance(metadata, dict):
            language = metadata.get("language")
    if not isinstance(language, str) or not language.strip():
        return "code"
    aliases = {"c++": "cpp", "cc": "cpp", "cxx": "cpp"}
    normalized = language.strip().lower()
    return aliases.get(normalized, normalized)


def _project_source_bundle(raw_bundle: object) -> dict | None:
    """Project one reachability source bundle into a prompt-safe shape.

    The bundle is generated from the effective graph, but it is still data
    supplied by a scan artifact.  Keep the schema bounded and preserve full
    function bodies for the selected path; the prompt renderer puts those
    bodies in safe code fences rather than interpolating them as instructions.
    """
    if not isinstance(raw_bundle, dict):
        return None
    projected: dict = {}
    for key in (
        "schema_version", "kind", "order", "source_complete", "node_count",
        "edge_count", "omitted_node_count",
    ):
        if key in raw_bundle:
            projected[key] = raw_bundle[key]
    nodes = raw_bundle.get("nodes")
    if isinstance(nodes, list):
        projected_nodes = []
        for raw_node in nodes[:24]:
            if not isinstance(raw_node, dict):
                continue
            node = {}
            for key in (
                "order", "id", "name", "file", "line_start", "line_end",
                "unit_type", "source", "source_length", "source_complete",
                "source_excerpt",
            ):
                value = raw_node.get(key)
                if value not in (None, "", []):
                    node[key] = value
            if node:
                projected_nodes.append(node)
        projected["nodes"] = projected_nodes
    edges = raw_bundle.get("edges")
    if isinstance(edges, list):
        projected["edges"] = [
            dict(edge) for edge in edges[:24] if isinstance(edge, dict)
        ]
    return projected


def _reachability_context_for_unit(unit: dict) -> dict | None:
    """Build a bounded, data-only summary of LLM reachability evidence.

    Reachability signals are advisory model output. Passing a small structured
    projection to Stage 1 makes the semantic-BFS decision auditable without
    copying the full batch response (or allowing arbitrary metadata to become
    prompt instructions). The vulnerability model must still validate source,
    propagation, sink, and guards independently.
    """
    raw_signals = unit.get("llm_reachability_signals")
    signals = raw_signals if isinstance(raw_signals, list) else []
    compact = []
    for raw in signals[:8]:
        if not isinstance(raw, dict):
            continue
        item = {}
        for key in (
            "kind", "confidence", "boundary", "direction", "evidence_status",
            "seed_status", "seed_reason", "evidence", "evidence_excerpt",
            "evidence_line_start", "evidence_line_end",
        ):
            value = raw.get(key)
            if value in (None, "", []):
                continue
            if isinstance(value, (str, int, float, bool)):
                item[key] = str(value)[:500] if isinstance(value, str) else value
        if item:
            compact.append(item)

    semantic_seed = unit.get("semantic_reachability_seed") is True
    semantic_retain_only = (
        unit.get("semantic_reachability_retain_only") is True
        or unit.get("reachability_retain_only") is True
    )
    sources = unit.get("reachability_seed_source")
    if isinstance(sources, list):
        sources = [str(value)[:120] for value in sources[:8]]
    elif sources:
        sources = [str(sources)[:120]]
    else:
        sources = []
    retain_sources = unit.get("reachability_retain_only_source")
    if isinstance(retain_sources, list):
        retain_sources = [str(value)[:120] for value in retain_sources[:8]]
    elif retain_sources:
        retain_sources = [str(retain_sources)[:120]]
    else:
        retain_sources = []
    if not compact and not semantic_seed and not semantic_retain_only and not sources:
        # A unit may have no LLM signal but still have a valuable, deterministic
        # entry-path context produced from effective_call_graph.json.
        lineage = unit.get("reachability_context")
        if not isinstance(lineage, dict):
            return None
    payload = {
        "semantic_reachability_seed": semantic_seed,
        "semantic_reachability_retain_only": semantic_retain_only,
        "reachability_retain_only": semantic_retain_only,
        "reachability_seed_source": sources,
        "reachability_retain_only_source": retain_sources,
        "signals": compact,
    }
    lineage = unit.get("reachability_context")
    if isinstance(lineage, dict):
        # Keep the prompt bounded and retain source-backed node identity/lines;
        # the model still has to re-check the actual target and sink.
        attack_chain = lineage.get("attack_chain_context")
        if not isinstance(attack_chain, dict):
            attack_chain = normalize_attack_chain_context()
        else:
            attack_chain = normalize_attack_chain_context(attack_chain)
        # The reachability context is built before enhancement.  Re-read the
        # unit here so a later single-shot ``llm_context.data_flow`` or a
        # structured callsite record is visible to Stage 1 without mutating
        # the original graph-derived artifact.  Merge observations conservatively.
        unit_attack_chain = context_from_unit(unit)
        if unit_attack_chain.get("status") != "not_evaluated":
            merged_callsites = list(attack_chain.get("callsite_contexts", []) or [])
            for candidate in unit_attack_chain.get("callsite_contexts", []) or []:
                if candidate not in merged_callsites:
                    merged_callsites.append(candidate)
            merged_missing = list(attack_chain.get("missing_evidence", []) or [])
            for missing in unit_attack_chain.get("missing_evidence", []) or []:
                if missing not in merged_missing:
                    merged_missing.append(missing)
            attack_chain = normalize_attack_chain_context({
                "status": "incomplete" if (
                    attack_chain.get("status") == "incomplete"
                    or unit_attack_chain.get("status") == "incomplete"
                ) else unit_attack_chain.get("status"),
                "complete": (
                    True if attack_chain.get("complete") is True
                    and unit_attack_chain.get("complete") is True else False
                ),
                "callsite_contexts": merged_callsites[:24],
                "missing_evidence": merged_missing[:32],
                "evidence": (
                    list(attack_chain.get("evidence", []) or [])
                    + list(unit_attack_chain.get("evidence", []) or [])
                )[:24],
                "provenance": "+".join(dict.fromkeys(filter(None, (
                    attack_chain.get("provenance"),
                    unit_attack_chain.get("provenance"),
                )))) or "not_provided",
            })
        legacy_stage1_status = lineage.get("stage1_context_status")
        if not legacy_stage1_status:
            legacy_stage1_status = (
                "strict" if lineage.get("entry_path_ids")
                or lineage.get("status") == "path_found" else
                "candidate" if lineage.get("candidate_entry_path_ids")
                or lineage.get("status") == "candidate_path_found" else
                "root" if lineage.get("status") == "root" else "unknown"
            )
        payload["entry_context"] = {
            "status": lineage.get("status"),
            "stage1_context_status": legacy_stage1_status,
            "stage1_context_analysis_allowed": lineage.get(
                "stage1_context_analysis_allowed", True
            ),
            "parameter_dataflow_is_stage1_gate": False,
            "stage1_context_missing_evidence": list(
                lineage.get("stage1_context_missing_evidence", []) or []
            )[:8],
            # Use the merged callsite context so post-enhancement Stage-2
            # observations are not hidden behind a stale pre-enhancement field.
            "stage2_dataflow_status": attack_chain.get("status"),
            "stage2_dataflow_complete": attack_chain.get("complete"),
            "stage2_dataflow_missing_evidence": list(
                attack_chain.get("missing_evidence", []) or []
            )[:12],
            "generic_entry_path_found": lineage.get(
                "generic_entry_path_found", bool(lineage.get("entry_path_ids"))
            ),
            "generic_entry_path_source_complete": lineage.get(
                "generic_entry_path_source_complete"
            ),
            "upstream_boundary_signals": [
                dict(signal) for signal in (lineage.get("upstream_boundary_signals", []) or [])[:16]
                if isinstance(signal, dict)
            ],
            "graph_versions": list(lineage.get("graph_versions", []) or [])[:4],
            "top_level_entry": lineage.get("top_level_entry"),
            "root_entry_points": list(lineage.get("root_entry_points", []) or [])[:4],
            "entry_path_ids": [
                list(path)[:24]
                for path in (lineage.get("entry_path_ids", []) or [])[:3]
                if isinstance(path, list)
            ],
            "entry_paths": [
                [
                    {
                        key: node.get(key)
                        for key in (
                            "id", "name", "file", "line_start", "line_end",
                            "unit_type", "source_excerpt",
                        )
                        if node.get(key) not in (None, "")
                    }
                    for node in path[:24]
                    if isinstance(node, dict)
                ]
                for path in (lineage.get("entry_paths", []) or [])[:3]
                if isinstance(path, list)
            ],
            # Keep the display-selected route separate from the strict and
            # candidate collections.  Stage 1 can see the most relevant
            # source-backed route while the provenance label remains explicit;
            # a candidate route is never silently promoted here.
            "primary_entry_path_kind": lineage.get("primary_entry_path_kind", "none"),
            "primary_entry_path_ids": [
                list(path)[:24]
                for path in (lineage.get("primary_entry_path_ids", []) or [])[:1]
                if isinstance(path, list)
            ],
            "primary_entry_path": [
                {
                    key: node.get(key)
                    for key in (
                        "id", "name", "file", "line_start", "line_end",
                        "unit_type", "source_excerpt",
                    )
                    if node.get(key) not in (None, "")
                }
                for node in (lineage.get("primary_entry_path", []) or [])[:24]
                if isinstance(node, dict)
            ],
            "primary_entry_path_edge_statuses": list(
                lineage.get("primary_entry_path_edge_statuses", []) or []
            )[:24],
            "primary_top_level_entry": lineage.get("primary_top_level_entry"),
            "primary_entry_path_source_complete": lineage.get(
                "primary_entry_path_source_complete"
            ),
            "primary_entry_path_full_source_complete": lineage.get(
                "primary_entry_path_full_source_complete"
            ),
            "primary_path_source_bundle": _project_source_bundle(
                lineage.get("primary_path_source_bundle")
            ),
            "supporting_context_bundle": _project_source_bundle(
                lineage.get("supporting_context_bundle")
            ),
            "primary_entry_path_validation": dict(
                lineage.get("primary_entry_path_validation", {})
            ) if isinstance(lineage.get("primary_entry_path_validation"), dict) else {},
            "candidate_entry_path_ids": [
                list(path)[:24]
                for path in (lineage.get("candidate_entry_path_ids", []) or [])[:3]
                if isinstance(path, list)
            ],
            "candidate_entry_paths": [
                [
                    {
                        key: node.get(key)
                        for key in (
                            "id", "name", "file", "line_start", "line_end",
                            "unit_type", "source_excerpt",
                        )
                        if node.get(key) not in (None, "")
                    }
                    for node in path[:24]
                    if isinstance(node, dict)
                ]
                for path in (lineage.get("candidate_entry_paths", []) or [])[:3]
                if isinstance(path, list)
            ],
            "candidate_entry_path_edge_statuses": [
                list(statuses)[:24]
                for statuses in (lineage.get("candidate_entry_path_edge_statuses", []) or [])[:3]
                if isinstance(statuses, list)
            ],
            "candidate_entry_path_edges": [
                [dict(edge) for edge in edges[:24] if isinstance(edge, dict)]
                for edges in (lineage.get("candidate_entry_path_edges", []) or [])[:3]
                if isinstance(edges, list)
            ],
            "candidate_path_count": lineage.get("candidate_path_count", 0),
            "candidate_missing_evidence": list(
                lineage.get("candidate_missing_evidence", []) or []
            )[:8],
            "upstream_complete": lineage.get("upstream_complete"),
            "missing_upstream_evidence": list(
                lineage.get("missing_upstream_evidence", []) or []
            )[:8],
            "attack_chain_context": attack_chain,
        }
    return payload


def parse_response(response: str) -> dict:
    """Parse JSON response from Claude."""
    # Try to extract JSON from response
    response = response.strip()

    # Remove markdown code blocks if present
    if response.startswith("```json"):
        response = response[7:]
    elif response.startswith("```"):
        response = response[3:]

    if response.endswith("```"):
        response = response[:-3]

    response = response.strip()

    err = None
    try:
        result = json.loads(response)
    except json.JSONDecodeError as e:
        err = e
    else:
        if isinstance(result, dict):
            return _normalize_result(result)
        # Top-level JSON that is NOT an object (e.g. an array-of-findings
        # `[{"verdict":...}]`) — do NOT hand a list to _normalize_result (it
        # indexes by str keys -> TypeError -> uncaught, permanent coverage loss,
        # PY-2). Fall through to the depth-0 scanner, which recovers a lone
        # verdict object inside the array for free.
    # Thinking-on models wrap the final JSON verdict in prose + code on BOTH
    # sides. Scan for verdict objects at brace-DEPTH 0 only, tracking JSON-string
    # state (with escapes) so braces inside string values -- or balanced code
    # braces in the preamble -- don't offset the depth. Recovering only depth-0
    # objects stops a nested example dict INSIDE a malformed outer verdict from
    # being mistaken for the verdict.
    #
    # Recover a verdict ONLY when EXACTLY ONE depth-0 object decodes to a
    # verdict-bearing dict AND no COMPETING verdict signal exists:
    #  - several decoded verdict objects (example beside the real one, either
    #    order) -> ambiguous -> ERROR+retry (never let a trailing example {SAFE}
    #    override a real {VULNERABLE}); and
    #  - a depth-0 span that FAILED to decode but still looks like a verdict
    #    object (its text carries "verdict"/"finding") is a real verdict that
    #    didn't parse (a common trailing-comma / missing-comma slip) sitting
    #    beside a clean example -> also ambiguous -> ERROR+retry. Without this,
    #    the malformed real VULNERABLE is dropped and the clean example SAFE is
    #    returned: a silent SAST false negative (PY-NEW-1).
    # If the scan ends mid-string, quote parity is untrustworthy -> don't guess.
    # (Accepted residual, pre-existing in the prior find/rfind code: adversarial
    # stray quotes in prose can still steer depth parity; the safe fallback is
    # always ERROR->retry.)
    decoder = json.JSONDecoder()
    verdict_objs = []
    malformed_verdict_spans = 0
    depth = 0
    in_string = False
    escape = False
    obj_start = None
    for pos, ch in enumerate(response):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            if depth == 0:
                obj_start = pos
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and obj_start is not None:
                    # Decode the balanced depth-0 span in isolation: bounds the
                    # JSONDecodeError position math to the span (avoids O(n^2) on
                    # multi-MB responses, PY-NEW-2) and gives the span text for
                    # the malformed-verdict check.
                    span = response[obj_start:pos + 1]
                    try:
                        obj = decoder.decode(span)
                        if isinstance(obj, dict) and ("verdict" in obj or "finding" in obj):
                            verdict_objs.append(obj)
                    except json.JSONDecodeError:
                        # Count as a competing verdict only if the failed span
                        # carries a verdict/finding KEY (quoted, single or double)
                        # -- so a malformed real verdict triggers the ambiguity
                        # guard, but a preamble code block that merely contains the
                        # word "finding" does not over-reject to ERROR.
                        # ACCEPTED TRADE-OFF: a preamble that echoes verdict-SHAPED
                        # broken JSON (e.g. `{"verdict": v}` in analyzed code) also
                        # counts, so a legit lone verdict beside it is sent to
                        # ERROR+retry rather than recovered. That is a recovery-rate
                        # cost, not a wrong verdict (the retry re-derives it) -- the
                        # deliberate safe direction, chosen over risking the
                        # PY-NEW-1 false negative (malformed real verdict beside a
                        # clean example -> example returned as SAFE).
                        if any(k in span for k in ('"verdict"', "'verdict'", '"finding"', "'finding'")):
                            malformed_verdict_spans += 1
                    obj_start = None
    if not in_string and len(verdict_objs) == 1 and malformed_verdict_spans == 0:
        return _normalize_result(verdict_objs[0])

    detail = str(err) if err is not None else "top-level JSON is not an object"
    return {
        "verdict": "ERROR",
        "confidence": 0,
        "vulnerabilities": [],
        "reasoning": f"Failed to parse response: {detail}",
        "raw_response": response[:500],
        # Tag the failure so the detection retry pass (core/analyzer.py) can
        # re-attempt it: a malformed model response is often transient, and
        # without this key the ERROR carries error=None and is never retried
        # in-run, permanently masking the unit's true verdict.
        "error": {"type": "parse_error", "message": detail[:200]},
    }


def analyze_unit(
    binding: PhaseBinding,
    unit: dict,
    use_multifile: bool = False,
    json_corrector: JSONCorrector = None,
    context_reviewer: ContextReviewer = None,
    app_context: "ApplicationContext" = None
) -> dict:
    """
    Analyze a single code unit.

    Args:
        binding: Phase binding (provider+model) for the analyze phase.
        unit: The code unit to analyze
        use_multifile: If True, use multi-file prompt for enhanced datasets
        json_corrector: Optional JSON corrector. If not provided, one is created
                        internally when parsing fails (matching behavior of other
                        LLM-calling components like finding_verifier and context_enhancer).
        context_reviewer: Optional context reviewer for proactive context enhancement
        app_context: Optional ApplicationContext for reducing false positives

    Returns analysis result with timing and token info.
    """
    # Extract code from unit
    code_field = unit.get("code", {})
    if isinstance(code_field, dict):
        code = code_field.get("primary_code", "")
        # Check if dependencies were inlined into this unit's primary_code
        primary_origin = code_field.get("primary_origin", {})
        has_deps_inlined = primary_origin.get("deps_inlined", primary_origin.get("enhanced", False))
        files_included = primary_origin.get("files_included", [])
    else:
        code = code_field
        has_deps_inlined = False
        files_included = []

    # Extract agent context (security classification from agentic parser)
    agent_context = unit.get("agent_context", {})
    security_classification = agent_context.get("security_classification")
    classification_reasoning = agent_context.get("reasoning")

    # Get route info
    route = unit.get("route") or {}
    if route:
        route_key = f"{route.get('method', 'GET')}:{route.get('path', '/unknown')}"
        handler = route.get("handler", "main")
    else:
        # Non-route unit: use unit ID as identifier
        route_key = unit.get("id", "unknown")
        handler = route_key.split(":")[-1] if ":" in route_key else route_key

    # New units carry their source language; old datasets keep the generic
    # code-fence fallback instead of being reinterpreted during migration.
    language = _unit_language(unit)
    platform_context = unit.get("platform_context")
    reachability_context = _reachability_context_for_unit(unit)

    # Proactively enhance context if reviewer is enabled
    context_enhanced = False
    additional_files_added = []
    if context_reviewer and use_multifile:
        print(f"      Reviewing context for missing files...")
        enhanced_code, enhanced_files = context_reviewer.enhance_context(
            code=code,
            route=route_key,
            handler=handler,
            files_included=files_included
        )
        if len(enhanced_files) > len(files_included):
            additional_files_added = [f for f in enhanced_files if f not in files_included]
            code = enhanced_code
            files_included = enhanced_files
            context_enhanced = True
            print(f"      Added {len(additional_files_added)} files via LLM review")

    # When the deterministic reachability stage supplied an ordered full-source
    # bundle, present only the target function in the primary code slot.  The
    # ordered entry-to-target bundle is rendered separately by the prompt
    # formatter, preventing the legacy breadth/depth dependency concatenation
    # from obscuring or reordering the actual route.  Keep ``code`` untouched
    # for result metadata, Stage 2, and legacy datasets without a bundle.
    code_for_prompt = code
    entry_context = (
        reachability_context.get("entry_context")
        if isinstance(reachability_context, dict)
        else None
    )
    source_bundle = (
        entry_context.get("primary_path_source_bundle")
        if isinstance(entry_context, dict)
        else None
    )
    if isinstance(source_bundle, dict) and source_bundle.get("nodes"):
        code_parts = split_on_boundary(code)
        if code_parts:
            code_for_prompt = code_parts[0].strip()

    # Generate prompt - single unified prompt for all cases
    prompt = get_analysis_prompt(
        code=code_for_prompt,
        language=language,
        route=route_key,
        files_included=files_included,
        security_classification=security_classification,
        classification_reasoning=classification_reasoning,
        app_context=app_context,
        platform_context=platform_context,
        reachability_context=reachability_context,
    )

    # Call the configured analyze-phase model with the threat-model system prompt.
    start_time = datetime.now()
    system_prompt = get_stage1_system_prompt(app_context=app_context)
    response = simple_text(binding, prompt, system=system_prompt)
    elapsed = (datetime.now() - start_time).total_seconds()

    # Parse response
    result = parse_response(response)

    # Derive the phase boundary before parsing correction.  It is attached
    # below, after a possible JSON-correction replacement, so malformed model
    # output cannot discard the Stage-1/Stage-2 handoff metadata.
    phase_context = stage_context_from_unit(unit)

    # If parsing failed or verdict is missing, try JSON correction
    if result.get("verdict") in ("ERROR", None):
        # Create JSONCorrector internally if not provided (same pattern as other components).
        # JSONCorrector inherits the analyze binding — correction calls
        # go to the same provider+model as the failing call.
        if json_corrector is None:
            json_corrector = JSONCorrector(binding)
        corrected = json_corrector.attempt_correction(response)
        corrected = _normalize_result(corrected)
        if corrected.get("verdict") not in ("ERROR", None):
            result = corrected

    # Persist the phase boundary alongside the model result.  Stage 1 remains
    # the vulnerability detector; the nested Stage-2 view only records which
    # parameter/data-flow facts still require tool-assisted verification.
    result["stage_context"] = phase_context
    result["stage1_context"] = phase_context.get("stage1", {})
    result["stage2_context"] = phase_context.get("stage2", {})
    result["stage1_context_status"] = result["stage1_context"].get("status", "unknown")
    result["stage2_dataflow_status"] = result["stage2_context"].get(
        "parameter_dataflow_status", "not_evaluated"
    )

    result["route_key"] = route_key
    result["elapsed_seconds"] = elapsed
    result["prompt_length"] = len(prompt)
    result["response_length"] = len(response)
    result["code_length"] = len(code)
    result["files_included"] = files_included
    result["has_deps_inlined"] = has_deps_inlined
    result["context_reviewed"] = context_enhanced
    if additional_files_added:
        result["files_added_by_review"] = additional_files_added

    # Track security classification from agentic parser
    if security_classification:
        result["security_classification"] = security_classification
        result["classification_reasoning"] = classification_reasoning

    return result
