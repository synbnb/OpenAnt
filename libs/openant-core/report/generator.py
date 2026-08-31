"""
Report Generator - generates security reports and disclosure documents from pipeline output.

Returns (text, usage_dict) tuples from LLM functions so callers can track costs.
"""

import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from dotenv import load_dotenv

from core.verdict_taxonomy import DISCLOSURE_ELIGIBLE
from core.language_registry import fence_for_path
from .schema import validate_pipeline_output, ValidationError
from utilities.file_io import normalize_results, open_utf8, read_json
from utilities.llm import (
    PhaseBinding,
    PhaseRegistry,
    build_phase_registry,
    load_config_file,
    lookup_pricing,
    resolve_llm_config,
)

load_dotenv()

PROMPTS_DIR = Path(__file__).parent / "prompts"
MAX_REPORT_PLATFORM_CONTEXT_CHARS = 2400


def _extract_usage(
    input_tokens: int,
    output_tokens: int,
    model: str,
    pricing: dict[str, float] | None = None,
) -> dict:
    """Build the usage dict from token counts.

    ``pricing`` is the adapter's rates for ``model`` (issue #65 §9 —
    pricing lives on the adapter, not on a shared global). When
    omitted, we fall back to the legacy ``MODEL_PRICING`` global so
    older call sites still produce a number; new code should always
    pass ``binding.adapter.pricing.get(binding.model)``.
    """
    if pricing is None:
        from utilities.llm_client import MODEL_PRICING

        pricing = MODEL_PRICING.get(model)
    if pricing is None:
        # Same one-time warning record_call emits, so an unknown model's
        # $0 cost isn't silently inconsistent between the two paths.
        from utilities.llm_client import _warn_unknown_pricing

        _warn_unknown_pricing(model)
        total_cost = 0.0
    else:
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        total_cost = input_cost + output_cost
    currency = str(pricing.get("currency", "USD") or "USD").strip().upper() if pricing else None
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        # Keep the historical USD key, but never put a CNY amount in it.
        "cost_usd": round(total_cost if currency == "USD" else 0.0, 6),
        "cost_amount": round(total_cost, 6),
        "cost_currency": currency,
        "cost_cny": round(total_cost if currency == "CNY" else 0.0, 6),
        "costs_by_currency": ({currency: round(total_cost, 6)}
                              if currency and total_cost else {}),
    }


def _merge_usage(usages: list[dict]) -> dict:
    """Merge multiple usage dicts into one."""
    merged = {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cost_usd": 0.0,
        "cost_cny": 0.0,
        "costs_by_currency": {},
    }
    for u in usages:
        merged["input_tokens"] += u["input_tokens"]
        merged["output_tokens"] += u["output_tokens"]
        merged["total_tokens"] += u["total_tokens"]
        merged["cost_usd"] = round(merged["cost_usd"] + u["cost_usd"], 6)
        merged["cost_cny"] = round(merged["cost_cny"] + u.get("cost_cny", 0.0), 6)
        usage_costs = u.get("costs_by_currency") or {}
        if not usage_costs and u.get("cost_usd"):
            usage_costs = {"USD": u["cost_usd"]}
        for currency, amount in usage_costs.items():
            merged["costs_by_currency"][currency] = round(
                merged["costs_by_currency"].get(currency, 0.0) + amount, 6
            )
    if len(merged["costs_by_currency"]) == 1:
        merged["cost_currency"], merged["cost_amount"] = next(
            iter(merged["costs_by_currency"].items())
        )
    else:
        merged["cost_currency"] = None
        merged["cost_amount"] = 0.0
    return merged


def load_prompt(name: str) -> str:
    """Load a prompt template from the prompts directory."""
    with open_utf8(PROMPTS_DIR / f"{name}.txt") as f:
        return f.read()


def merge_dynamic_results(pipeline_data: dict, pipeline_path: str) -> dict:
    """Merge dynamic test results into pipeline findings if available.

    Looks for dynamic_test_results.json next to the pipeline_output.json file
    and adds a 'dynamic_testing' key to each matching finding.
    """
    dynamic_path = Path(pipeline_path).parent / "dynamic_test_results.json"
    if not dynamic_path.exists():
        return pipeline_data

    dynamic_data = read_json(dynamic_path)
    # fa17 TRUST BOUNDARY: dynamic_test_results.json `results` is model-supplied;
    # normalize to dicts-only once so the `result.get("finding_id")` loop below
    # never calls `.get()` on a bare string/number.
    normalize_results(dynamic_data)
    results_by_id = {}
    for result in dynamic_data.get("results", []):
        fid = result.get("finding_id")
        if fid:
            results_by_id[fid] = result

    if not results_by_id:
        return pipeline_data

    from datetime import datetime
    date_str = datetime.fromtimestamp(dynamic_path.stat().st_mtime).strftime("%B %Y")

    for finding in pipeline_data.get("findings", []):
        fid = finding.get("id")
        if fid and fid in results_by_id:
            r = results_by_id[fid]
            finding["dynamic_testing"] = {
                "status": r.get("status"),
                "details": r.get("details"),
                "evidence": r.get("evidence", []),
                "tested": f"Docker container, {date_str}",
            }

    print(f"  Merged {len(results_by_id)} dynamic test results from {dynamic_path.name}", file=sys.stderr)
    return pipeline_data


def _compact_for_summary(pipeline_data: dict) -> dict:
    """Create a compact copy of pipeline_data for the summary prompt.

    Strips large fields (vulnerable_code, steps_to_reproduce, description)
    from findings to avoid exceeding the context window.
    """
    compact = {k: v for k, v in pipeline_data.items() if k != "findings"}
    compact["findings"] = []
    for f in pipeline_data.get("findings", []):
        compact["findings"].append({
            "id": f.get("id"),
            "name": f.get("name"),
            "short_name": f.get("short_name"),
            "location": f.get("location"),
            "cwe_id": f.get("cwe_id"),
            "cwe_name": f.get("cwe_name"),
            "stage1_verdict": f.get("stage1_verdict"),
            "stage2_verdict": f.get("stage2_verdict"),
            "dynamic_testing": f.get("dynamic_testing"),
            "impact": f.get("impact"),
        })
    return compact


def _context_provenance_header(pipeline_data: dict) -> str:
    """R5: a deterministic banner when context came from a repo-controlled file.

    Rendered from ``pipeline_output.json`` fields WITHOUT the LLM, on purpose: a
    threat model is attacker-influenceable (it ships in the scanned repo), so the
    notice that the security model came from that file must not be something a
    hostile file can suppress by steering the report prompt.  OpenHarmony's
    operator-owned platform baseline is also disclosed here, including for a
    generated context, because its presence changes the effective attacker model.
    """
    baseline = (
        pipeline_data.get("application_context_provenance") or {}
    ).get("platform_baseline")
    baseline_applied = isinstance(baseline, dict) and baseline.get("applied") is True
    if pipeline_data.get("context_source") != "threat_model" and not baseline_applied:
        return ""
    lines = []
    if pipeline_data.get("context_source") == "threat_model":
        lines.extend(
            [
                "> **⚠ Security model supplied by a repo-controlled file.**",
                "> This scan's attacker model came from `OPENANT.THREATMODEL.md` inside "
                "the scanned repository, which is attacker-influenceable. Treat the "
                "findings' scope as only as trustworthy as that file.",
            ]
        )
        sha = pipeline_data.get("threat_model_sha256")
        if sha:
            lines.append(f"> Threat-model sha256: `{sha}`")
        for warning in pipeline_data.get("threat_model_warnings") or []:
            lines.append(f"> - {warning}")
    if baseline_applied:
        lines.append(
            "> **OpenHarmony platform minimum baseline applied (mandatory).**"
        )
        if baseline.get("version") is not None:
            lines.append(f"> Baseline version: `{baseline.get('version')}`")
        conflicts = (
            pipeline_data.get("application_context_provenance") or {}
        ).get("merge_conflicts") or []
        if conflicts:
            lines.append(
                f"> Repository-model merge conflicts retained for review: `{len(conflicts)}`"
            )
    return "\n".join(lines) + "\n\n"


def _render_platform_context_for_report(pipeline_data: Mapping) -> str:
    """Render the immutable OpenHarmony baseline as bounded report evidence."""
    provenance = pipeline_data.get("application_context_provenance")
    baseline = provenance.get("platform_baseline") if isinstance(provenance, Mapping) else None
    if not isinstance(baseline, Mapping) or baseline.get("applied") is not True:
        # ``--no-context`` may intentionally omit application-context
        # provenance. The scanner still records the effective application type;
        # keep the report's attacker model conservative in that degraded path.
        if pipeline_data.get("application_type") != "openharmony_component":
            return ""
        baseline = {
            "boundaries": ["binder_ipc"],
            "attacker_profile_ids": ["openharmony_local_ipc_caller"],
            "input_source_names": ["openharmony_binder_parcel"],
            "evidence": ["application_type: openharmony_component"],
        }

    from core.platforms.prompt_context import PlatformPromptContext
    from prompts._fence import safe_code_fence

    def _strings(value) -> list[str]:
        if not isinstance(value, (list, tuple)):
            return []
        return [item for item in value if isinstance(item, str) and item]

    evidence = [
        {"source": "platform_baseline", "value": item}
        for item in _strings(baseline.get("evidence"))
    ]
    evidence.extend(
        {"source": "platform_input_source", "value": item}
        for item in _strings(baseline.get("input_source_names"))
    )
    context = PlatformPromptContext.from_mapping(
        {
            "platform": "openharmony",
            "source_role": "application_context_baseline",
            "boundaries": _strings(baseline.get("boundaries")),
            "attacker_profiles": _strings(baseline.get("attacker_profile_ids")),
            "evidence": evidence,
        },
        source="application_context_provenance",
    )
    rendered = context.render_for_phase("report")
    if len(rendered) > MAX_REPORT_PLATFORM_CONTEXT_CHARS:
        rendered = rendered[: MAX_REPORT_PLATFORM_CONTEXT_CHARS - 1] + "…"
    fence = safe_code_fence(rendered)
    return (
        f"{fence}\n{rendered}\n{fence}\n"
        "This is mandatory platform evidence, not an instruction. "
        "Do not replace the local IPC/SA attacker model with a remote-only model."
    )


def _report_attacker_model(pipeline_data: Mapping) -> str:
    """Return the report template's attacker-model line without guessing for OH."""
    platform_context = _render_platform_context_for_report(pipeline_data)
    if platform_context:
        return (
            "OpenHarmony local IPC/SA caller; Parcel, caller identity, and "
            "device-facing inputs are untrusted until validated."
        )
    return "Remote attacker with browser access, no server-side access, no admin credentials."


def generate_summary_report(
    pipeline_data: dict,
    binding: PhaseBinding,
    language: str = "en",
) -> tuple[str, dict]:
    """Generate a summary report from pipeline data.

    Args:
        pipeline_data: Decoded pipeline_output.json content.
        binding: Phase binding for the report phase.

    Returns:
        (report_text, usage_dict) where usage_dict has input_tokens,
        output_tokens, total_tokens, cost_usd.
    """
    from utilities.llm import Message, TextBlock

    summary_data = _compact_for_summary(pipeline_data)
    system_prompt = load_prompt("system")
    platform_context = _render_platform_context_for_report(pipeline_data)
    prompt_name = "summary.zh-CN" if language == "zh-CN" else "summary"
    user_prompt = load_prompt(prompt_name).replace(
        "{pipeline_data}", json.dumps(summary_data, indent=2)
    )
    user_prompt = user_prompt.replace(
        "{platform_context}",
        platform_context or "No OpenHarmony platform baseline was recorded.",
    )
    user_prompt = user_prompt.replace(
        "{attacker_model}", _report_attacker_model(pipeline_data)
    )

    result = binding.adapter.complete(
        model=binding.model,
        max_tokens=4096,
        system=system_prompt,
        messages=[Message(role="user", content=[TextBlock(user_prompt)])],
    )

    text = "\n".join(b.text for b in result.content if isinstance(b, TextBlock))
    # Prepend the provenance banner deterministically (see helper docstring).
    text = _context_provenance_header(pipeline_data) + text
    return text, _extract_usage(
        result.input_tokens,
        result.output_tokens,
        binding.model,
        pricing=lookup_pricing(binding),
    )


def _splice_code_section(llm_output: str, code_section: str) -> str:
    """Insert the verbatim code block into the LLM-generated disclosure.

    The LLM generates everything except the Vulnerable Code section. This
    function inserts the server-built code block at the right position.

    As a safety net, if the LLM ignored the instruction and still generated
    its own ``## Vulnerable Code`` block, that block is stripped first.
    """
    if not code_section:
        return llm_output

    # Safety net: strip any LLM-generated Vulnerable Code section.
    # Matches from "## Vulnerable Code" up to the next ## heading or end of string.
    output = re.sub(
        r'## Vulnerable Code.*?(?=\n## |\Z)',
        '',
        llm_output,
        flags=re.DOTALL,
    )

    # Insert the real code section before "## Steps to Reproduce".
    insertion_point = '## Steps to Reproduce'
    if insertion_point in output:
        output = output.replace(
            insertion_point,
            f"{code_section}\n\n{insertion_point}",
            1,
        )
    else:
        # Fallback: insert before "## Impact" if Steps is missing.
        fallback = '## Impact'
        if fallback in output:
            output = output.replace(fallback, f"{code_section}\n\n{fallback}", 1)
        else:
            output += f"\n\n{code_section}"

    return output


def _finding_location(vulnerability_data: Mapping) -> tuple[str, str]:
    """Return the report file/function pair without trusting model shapes."""
    location = vulnerability_data.get("location")
    if not isinstance(location, Mapping):
        location = {}
    file_path = str(location.get("file") or "unknown")
    function = str(location.get("function") or "unknown")
    return file_path, function


def _disclosure_title(vulnerability_data: Mapping) -> str:
    """Choose a useful title when the model only supplied a verdict label."""
    generic = {"", "vulnerable", "bypassable", "safe", "inconclusive", "unknown"}
    name = str(vulnerability_data.get("name") or "").strip()
    if name.lower() not in generic:
        return name
    cwe_name = str(vulnerability_data.get("cwe_name") or "").strip()
    if cwe_name and cwe_name.lower() != "unknown":
        return cwe_name
    _file_path, function = _finding_location(vulnerability_data)
    return f"Security issue in {function}"


def _report_affected_versions(pipeline_data: Mapping) -> str:
    """Render a deterministic revision marker instead of ``[NOT PROVIDED]``."""
    repository = pipeline_data.get("repository")
    repository = repository if isinstance(repository, Mapping) else {}
    for key in ("affected_versions", "version", "release", "release_version"):
        value = repository.get(key) or pipeline_data.get(key)
        if value:
            return str(value)
    commit = repository.get("commit_sha") or pipeline_data.get("commit_sha")
    if commit:
        return f"Current scanned revision (commit {commit})"
    return "Current scanned revision (release version not provided)"


def _report_analysis_date(pipeline_data: Mapping) -> str:
    value = pipeline_data.get("analysis_date") or pipeline_data.get("timestamp")
    if not value:
        return "date not recorded"
    return str(value)


def _report_platform_version(pipeline_data: Mapping) -> str:
    if pipeline_data.get("application_type") == "openharmony_component":
        return "OpenHarmony"
    return str(pipeline_data.get("platform") or "application platform")


def _report_verification_method(vulnerability_data: Mapping) -> str:
    if vulnerability_data.get("dynamic_testing"):
        return "dynamic testing"
    verdict = str(vulnerability_data.get("stage2_verdict") or "").lower()
    if verdict in {"confirmed", "agreed"}:
        return "attacker simulation (Stage 2)"
    return "static analysis"


def _report_language(file_path: str, pipeline_data: Mapping) -> str:
    suffix = Path(file_path).suffix.lower()
    suffixes = {
        ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
        ".h": "cpp", ".hpp": "cpp", ".py": "python", ".java": "java",
        ".js": "javascript", ".ts": "typescript", ".go": "go", ".rs": "rust",
    }
    return suffixes.get(suffix, str(pipeline_data.get("language") or "text"))


def _artifact_code_by_route(payload) -> dict[str, str]:
    """Read a route-to-source map from a sibling scan artifact."""
    if not isinstance(payload, Mapping):
        return {}
    direct = payload.get("code_by_route")
    if isinstance(direct, Mapping):
        result = {}
        for route, value in direct.items():
            if not isinstance(route, str):
                continue
            if isinstance(value, str) and value:
                result[route] = value
            elif isinstance(value, Mapping):
                code = value.get("code") or value.get("source_code") or value.get("source")
                if isinstance(code, str) and code:
                    result[route] = code
        if result:
            return result
    functions = payload.get("functions")
    if isinstance(functions, Mapping):
        result = {}
        for route, value in functions.items():
            if not isinstance(route, str) or not isinstance(value, Mapping):
                continue
            code = value.get("code") or value.get("source_code") or value.get("source")
            if isinstance(code, str) and code:
                result[route] = code
        return result
    return {}


def _hydrate_pipeline_findings(pipeline_path: str, pipeline_data: dict) -> dict:
    """Backfill source sections for pipeline files produced before the fix.

    This is intentionally in-memory: the original pipeline artifact is not
    rewritten.  It only makes a subsequent report regeneration use the source
    already present in ``results_verified.json``, ``results.json``, or
    ``call_graph.json`` beside the pipeline file.
    """
    findings = pipeline_data.get("findings")
    if not isinstance(findings, list):
        return pipeline_data

    source_map = {}
    scan_dir = Path(pipeline_path).resolve().parent
    for name in ("results_verified.json", "results.json", "call_graph.json"):
        candidate = scan_dir / name
        try:
            if candidate.is_file():
                recovered = _artifact_code_by_route(read_json(candidate))
                for route, code in recovered.items():
                    source_map.setdefault(route, code)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    if not source_map:
        return pipeline_data

    language = ""
    repository = pipeline_data.get("repository")
    if isinstance(repository, Mapping):
        language = str(repository.get("language") or "")
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        location = finding.get("location")
        if not isinstance(location, Mapping):
            continue
        file_path = str(location.get("file") or "unknown")
        function = str(location.get("function") or "unknown")
        route = f"{file_path}:{function}"
        code = finding.get("vulnerable_code") or source_map.get(route)
        if not isinstance(code, str) or not code:
            continue
        finding["vulnerable_code"] = code
        if not finding.get("vulnerable_code_section"):
            fence = fence_for_path(file_path, fallback=language or "text")
            finding["vulnerable_code_section"] = (
                "## Vulnerable Code\n\n"
                f"`{file_path}`:\n\n"
                f"```{fence}\n{code}\n```"
            )
    return pipeline_data


def _fallback_code_section(vulnerability_data: Mapping) -> str:
    """Keep the disclosure schema complete when source evidence is absent."""
    file_path, function = _finding_location(vulnerability_data)
    return (
        "## Vulnerable Code\n\n"
        f"`{file_path}` / `{function}`\n\n"
        "> Source code was not preserved in the available scan artifacts. "
        "Review the referenced function in the repository before disclosure."
    )


def _heading_present(text: str, heading: str) -> bool:
    return bool(re.search(rf"(?im)^##\s+{re.escape(heading)}\s*$", text or ""))


def _ensure_disclosure_sections(
    text: str,
    vulnerability_data: Mapping,
    metadata: Mapping,
    code_section: str,
) -> str:
    """Fill mandatory report fields the LLM omitted or left as placeholders.

    LLM output remains the narrative source, but the report contract is
    enforced deterministically.  This prevents a short/early model response
    from yielding a file that is syntactically present yet unusable to a
    reviewer.
    """
    output = (text or "").strip()
    title = _disclosure_title(vulnerability_data)
    if not output:
        output = f"# Security Disclosure: {title}"

    # Ensure the three metadata lines are visible even if the model omitted
    # the requested header.  Insert them after the first title when possible.
    metadata_lines = {
        "**Product:**": f"**Product:** {metadata.get('product_name') or 'unknown'}",
        "**Type:**": (
            f"**Type:** CWE-{vulnerability_data.get('cwe_id') or 0} "
            f"({vulnerability_data.get('cwe_name') or 'Unknown'})"
        ),
        "**Affected:**": f"**Affected:** {metadata.get('affected_versions')}",
    }
    missing_metadata = []
    for marker, line in metadata_lines.items():
        existing = re.search(rf"(?im)^{re.escape(marker)}.*$", output)
        if existing and not re.search(r"\[(?:NOT PROVIDED|REQUIRES MANUAL INPUT)\]", existing.group(0), re.I):
            continue
        if existing:
            output = output[:existing.start()] + line + output[existing.end():]
        else:
            missing_metadata.append(line)
    if missing_metadata:
        title_match = re.search(r"(?m)^#\s+.+$", output)
        if title_match:
            pos = title_match.end()
            output = output[:pos] + "\n\n" + "\n".join(missing_metadata) + output[pos:]
        else:
            output = "\n".join(missing_metadata) + "\n\n" + output

    fallbacks = {
        "Summary": str(vulnerability_data.get("description") or (
            "The analysis identified a security-relevant condition in the "
            "reported function; confirm the exact behavior during review."
        )),
        "Steps to Reproduce": str(vulnerability_data.get("steps_to_reproduce") or (
            "[REQUIRES DYNAMIC TESTING] Reproduce the call with a controlled "
            "local harness and record the input, caller identity, and result."
        )),
        "Impact": str(vulnerability_data.get("impact") or (
            "Impact is not available from the supplied analysis fields; confirm "
            "the affected operation manually."
        )),
        "Suggested Fix": str(vulnerability_data.get("suggested_fix") or (
            "[MANUAL REVIEW REQUIRED] Add the missing validation or authorization "
            "at the identified trust boundary after confirming intended behavior."
        )),
    }

    tested_line = (
        f"**Tested:** {metadata.get('platform_version') or 'application platform'}, "
        f"{metadata.get('analysis_date') or 'date not recorded'}."
    )
    tested_match = re.search(r"(?im)^\*\*Tested:\*\*.*$", output)
    if tested_match:
        if re.search(r"\[(?:NOT PROVIDED|REQUIRES MANUAL INPUT)\]", tested_match.group(0), re.I):
            output = output[:tested_match.start()] + tested_line + output[tested_match.end():]
    else:
        # The Tested line is part of the disclosure contract even though it is
        # not a level-2 section.  Add it next to the affected metadata.
        output = output.replace(metadata_lines["**Affected:**"],
                                metadata_lines["**Affected:**"] + "\n" + tested_line,
                                1)

    # Keep the source section ahead of the reproduction steps.  It is already
    # deterministic and may contain a verbatim parser snippet.
    if not _heading_present(output, "Vulnerable Code"):
        insertion = "\n\n" + (code_section or _fallback_code_section(vulnerability_data))
        marker = "## Steps to Reproduce"
        if marker in output:
            output = output.replace(marker, insertion + "\n\n" + marker, 1)
        else:
            output += insertion

    for heading, fallback in fallbacks.items():
        heading_match = re.search(rf"(?ims)^##\s+{re.escape(heading)}\s*$.*?(?=^##\s|^---\s*$|\Z)", output)
        if not heading_match:
            output += f"\n\n## {heading}\n\n{fallback}"
            continue
        body = heading_match.group(0)
        # Models commonly emit a heading but no content, or copy the template's
        # placeholder.  Replace only those non-evidence bodies; substantive
        # model prose remains untouched.
        if re.search(r"\[(?:NOT PROVIDED|REQUIRES MANUAL INPUT)\]", body, re.I):
            replacement = f"## {heading}\n\n{fallback}\n"
            output = output[:heading_match.start()] + replacement + output[heading_match.end():]

    return output.strip() + "\n"


def generate_disclosure(
    vulnerability_data: dict,
    product_name: str,
    binding: PhaseBinding,
    pipeline_data: Mapping | None = None,
) -> tuple[str, dict]:
    """Generate a disclosure document for a single vulnerability.

    Args:
        vulnerability_data: Finding to disclose.
        product_name: Repository / product name.
        binding: Phase binding for the report phase.
        pipeline_data: Optional pipeline output carrying platform provenance.

    Returns:
        (disclosure_text, usage_dict)
    """
    from utilities.llm import Message, TextBlock

    system_prompt = load_prompt("system")

    # The vulnerable-code markdown block is spliced into the LLM output
    # AFTER generation — the LLM never sees or produces it. This prevents
    # the LLM from hallucinating the snippet.
    report_data = pipeline_data if isinstance(pipeline_data, Mapping) else {}
    file_path, _function = _finding_location(vulnerability_data)
    code_section = vulnerability_data.get("vulnerable_code_section") or ""
    if not isinstance(code_section, str):
        code_section = str(code_section)
    if not code_section:
        code_section = _fallback_code_section(vulnerability_data)
    payload = {
        k: v for k, v in vulnerability_data.items()
        if k not in ("vulnerable_code_section", "vulnerable_code")
    }
    payload["product_name"] = product_name

    affected_versions = _report_affected_versions(report_data)
    replacements = {
        "short_title": _disclosure_title(vulnerability_data),
        "product_name": product_name or "unknown",
        "cwe_id": vulnerability_data.get("cwe_id") or 0,
        "cwe_name": vulnerability_data.get("cwe_name") or "Unknown",
        "affected_versions": affected_versions,
        "platform_version": _report_platform_version(report_data),
        "analysis_date": _report_analysis_date(report_data),
        "verification_method": _report_verification_method(vulnerability_data),
        "language": _report_language(file_path, report_data),
        "fixed_code_snippet": vulnerability_data.get("suggested_fix") or (
            "// Manual review required: add the appropriate validation or "
            "authorization check."
        ),
    }
    user_prompt = load_prompt("disclosure")
    user_prompt = user_prompt.replace(
        "{vulnerability_data}", json.dumps(payload, indent=2), 1
    )
    user_prompt = user_prompt.replace(
        "{platform_context}",
        _render_platform_context_for_report(report_data)
        or "No OpenHarmony platform baseline was recorded.",
    )
    user_prompt = user_prompt.replace(
        "{attacker_model}", _report_attacker_model(report_data)
    )
    for key, value in replacements.items():
        user_prompt = user_prompt.replace("{" + key + "}", str(value))

    result = binding.adapter.complete(
        model=binding.model,
        max_tokens=4096,
        system=system_prompt,
        messages=[Message(role="user", content=[TextBlock(user_prompt)])],
    )

    llm_output = "\n".join(
        b.text for b in result.content if isinstance(b, TextBlock)
    )
    final_output = _splice_code_section(llm_output, code_section)
    final_output = _ensure_disclosure_sections(
        final_output,
        vulnerability_data,
        {
            "product_name": product_name,
            "affected_versions": affected_versions,
            "platform_version": replacements["platform_version"],
            "analysis_date": replacements["analysis_date"],
        },
        code_section,
    )

    return final_output, _extract_usage(
        result.input_tokens,
        result.output_tokens,
        binding.model,
        pricing=lookup_pricing(binding),
    )


def generate_all(
    pipeline_path: str,
    output_dir: str,
    registry: PhaseRegistry | None = None,
    llm_config_name: str | None = None,
) -> None:
    """Generate all reports from a pipeline output file."""
    pipeline_data = read_json(pipeline_path)
    # Historical pipeline_output.json files may predate source preservation in
    # the verifier.  Hydrate their in-memory findings from sibling artifacts
    # before disclosure generation; the original JSON remains unchanged.
    pipeline_data = _hydrate_pipeline_findings(pipeline_path, pipeline_data)
    # fa18 TRUST BOUNDARY: normalize model `findings` to dicts-only once at load
    # so the summary compaction and the disclosure enumerate below iterate
    # dicts-only. Presence-guarded so an absent `findings` still fails
    # validate_pipeline_output's "missing required field" check.
    if "findings" in pipeline_data:
        normalize_results(pipeline_data, "findings")

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Resolve the report-phase binding once and reuse for every call.
    if registry is None:
        cf = load_config_file()
        registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
    report_binding = registry.get("report")

    # Generate summary report
    print("Generating summary report...")
    summary, _usage = generate_summary_report(pipeline_data, report_binding)
    with open_utf8(output_path / "SUMMARY_REPORT.md", "w") as f:
        f.write(summary)
    print(f"  -> {output_path / 'SUMMARY_REPORT.md'}")

    # Generate disclosure for each confirmed vulnerability
    disclosures_dir = output_path / "disclosures"
    disclosures_dir.mkdir(exist_ok=True)

    product_name = pipeline_data["repository"]["name"]

    for i, finding in enumerate(pipeline_data["findings"], 1):
        # Disclosure eligibility is defined once in
        # core.verdict_taxonomy.DISCLOSURE_ELIGIBLE, shared with
        # core/reporter.generate_disclosure_docs and report/__main__, so a
        # degenerate verify never silently drops a Stage-1 potential vuln.
        if finding.get("stage2_verdict") not in DISCLOSURE_ELIGIBLE:
            continue

        print(f"Generating disclosure for {finding['short_name']}...")
        disclosure, _usage = generate_disclosure(
            finding,
            product_name,
            report_binding,
            pipeline_data=pipeline_data,
        )

        # short_name passes validation on presence only, so it may be null/empty,
        # a non-str (JSON), or contain a "/" — fall back to id, coerce to str, and
        # basename it so a null/typed/traversal short_name can't crash disclosure
        # generation (AttributeError / FileNotFoundError writing into a missing dir).
        safe_name = (os.path.basename(str(finding.get("short_name") or finding.get("id") or "finding"))
                     or "finding").replace(" ", "_").upper()
        filename = f"DISCLOSURE_{i:02d}_{safe_name}.md"
        with open_utf8(disclosures_dir / filename, "w") as f:
            f.write(disclosure)
        print(f"  -> {disclosures_dir / filename}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python generator.py <pipeline_output.json> <output_dir>")
        sys.exit(1)

    generate_all(sys.argv[1], sys.argv[2])
    print("Done.")
