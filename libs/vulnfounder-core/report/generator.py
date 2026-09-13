"""
Report Generator - generates security reports and disclosure documents from pipeline output.

Returns (text, usage_dict) tuples from LLM functions so callers can track costs.
"""

import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from dotenv import load_dotenv

from core.verdict_taxonomy import DISCLOSURE_ELIGIBLE
from core.language_registry import fence_for_path
from core.report_context import build_disclosure_context, load_report_context_index
from core.finding_records import normalize_findings
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
MAX_REPAIR_SOURCE_CHARS = 24_000
MAX_REPAIR_CONTEXT_CHARS = 32_000
_REPAIR_PLACEHOLDER_MARKERS = (
    "[MANUAL REVIEW",
    "[REQUIRES MANUAL",
    "manual review required",
    "review the referenced function",
    "add the missing validation",
    "add the appropriate validation",
)


# Disclosure documents have two independent language concerns: the report
# locale (English/Chinese) and the code-fence language (C/C++/Python, ...).
# Keep the locale vocabulary in one place so deterministic sections use the
# same headings as the localized LLM prompt.  The default English values are
# intentionally identical to the historical report contract.
_DISCLOSURE_LABELS = {
    "en": {
        "title": "Security Disclosure",
        "product": "Product",
        "type": "Type",
        "affected": "Affected",
        "tested": "Tested",
        "summary": "Summary",
        "steps": "Steps to Reproduce",
        "impact": "Impact",
        "fix": "Suggested Fix",
        "code": "Vulnerable Code",
        "context": "Evidence Context",
        "target_location": "Target Source Location",
        "source_sink": "Source-to-Sink Evidence",
        "call_chain": "Call Chain Source",
        "call_graph": "Call Graph Evidence",
        "core": "Core Vulnerability Evidence",
        "description": "Vulnerability Description",
        "trigger": "Triggering Code",
        "attack_chain": "Attack Chain",
        "call_chain_overview": "Call Chain Overview",
        "strict_chains": "Strict call chains",
        "candidate_chains": "Candidate call chains",
        "no_call_chain_overview": "No strict or candidate call-chain paths were preserved.",
        "root_cause": "Root Cause",
        "fix_points": "Remediation Key Points",
        "scenario": "Attack scenario",
        "granularity": "Evidence granularity",
        "dataflow_status": "Stage-2 data-flow status",
        "issue_inventory": "Independent Issue Inventory",
        "function": "Function",
        "file": "File",
        "route": "Route key",
        "entry": "Entry point",
        "ordered_flow": "Ordered data flow",
        "dataflow": "Data-flow summary",
        "attack": "Attack scenario",
        "route_chain": "Function route chain",
        "sink_reached": "Sink reached",
        "attacker_control": "Attacker control at sink",
        "path_broken": "Path broken at",
        "native_edges": "Native edges",
        "semantic_edges": "Semantic edges",
        "projected_edges": "Projected/recovered edges",
        "statistics": "Graph statistics",
        "recovery": "Recovery summary",
        "coverage": "Coverage note",
        "no_graph": "No local graph edge connected the selected context nodes.",
        "artifacts": "Evidence artifacts",
        "source_missing": "No call-chain function source was preserved in the available artifacts.",
        "deterministic_note": (
            "This section is generated deterministically from scan artifacts; "
            "source and line numbers were not rewritten by the LLM. Missing "
            "content means the corresponding evidence was not preserved."
        ),
    },
    "zh-CN": {
        "title": "安全漏洞披露",
        "product": "产品",
        "type": "类型",
        "affected": "影响版本",
        "tested": "测试环境",
        "summary": "摘要",
        "steps": "复现步骤",
        "impact": "影响",
        "fix": "建议修复",
        "code": "漏洞代码",
        "context": "证据上下文",
        "target_location": "目标源码位置",
        "source_sink": "源到汇证据",
        "call_chain": "调用链源码",
        "call_graph": "调用图证据",
        "core": "漏洞核心证据",
        "description": "漏洞说明",
        "trigger": "漏洞触发代码",
        "attack_chain": "攻击链",
        "call_chain_overview": "调用链总览",
        "strict_chains": "严格调用链",
        "candidate_chains": "候选调用链",
        "no_call_chain_overview": "当前产物没有保存严格或候选调用链。",
        "root_cause": "漏洞根因",
        "fix_points": "修复要点",
        "scenario": "攻击场景",
        "granularity": "证据粒度",
        "dataflow_status": "Stage 2 数据流状态",
        "issue_inventory": "独立问题清单",
        "function": "函数",
        "file": "文件",
        "route": "路由键",
        "entry": "入口",
        "ordered_flow": "有序数据流",
        "dataflow": "数据流摘要",
        "attack": "攻击场景",
        "route_chain": "函数路由链",
        "sink_reached": "是否到达汇",
        "attacker_control": "攻击者在汇点的控制能力",
        "path_broken": "路径中断位置",
        "native_edges": "原生调用边",
        "semantic_edges": "语义调用边",
        "projected_edges": "投影/恢复调用边",
        "statistics": "调用图统计",
        "recovery": "恢复摘要",
        "coverage": "覆盖范围说明",
        "no_graph": "选定的上下文节点之间没有保存本地调用图边。",
        "artifacts": "证据来源产物",
        "source_missing": "可用产物中没有保存调用链函数源码。",
        "deterministic_note": (
            "本节由扫描产物确定性生成，源码和行号未经过大模型改写；缺失内容表示扫描时没有保存对应证据。"
        ),
    },
}


def _disclosure_locale(language: str | None) -> str:
    """Normalize a disclosure locale while keeping legacy calls English."""
    return "zh-CN" if language == "zh-CN" else "en"


def _disclosure_labels(language: str | None) -> dict[str, str]:
    return _DISCLOSURE_LABELS[_disclosure_locale(language)]


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
        inventory = normalize_findings(
            f.get("independent_findings") or f.get("findings"),
            primary_finding=f.get("stage1_verdict") or f.get("stage2_verdict"),
            synthesize_primary=True,
        )
        compact["findings"].append({
            "id": f.get("id"),
            "name": f.get("name"),
            "short_name": f.get("short_name"),
            "location": f.get("location"),
            "cwe_id": f.get("cwe_id"),
            "cwe_name": f.get("cwe_name"),
            "stage1_verdict": f.get("stage1_verdict"),
            "stage2_verdict": f.get("stage2_verdict"),
            "review_status": f.get("review_status"),
            "verification_assessment": f.get("verification_assessment"),
            "dynamic_testing": f.get("dynamic_testing"),
            "impact": f.get("impact"),
            # Keep the summary model aware that one context can contain more
            # than one issue, while dropping long source/reasoning fields.
            "independent_findings": [
                {
                    key: record.get(key)
                    for key in (
                        "finding_id", "scope", "relation", "target_match",
                        "finding", "function_analyzed", "file", "line_start",
                        "line_end", "vulnerability_categories", "impact",
                    )
                    if record.get(key) not in (None, "", [])
                }
                for record in inventory[:16]
            ],
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
                "> This scan's attacker model came from `VULNFOUNDER.THREATMODEL.md` "
                "(or the legacy `OPENANT.THREATMODEL.md`) inside "
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


def _splice_code_section(
    llm_output: str,
    code_section: str,
    language: str = "en",
) -> str:
    """Insert the verbatim code block into the LLM-generated disclosure.

    The LLM generates everything except the Vulnerable Code section. This
    function inserts the server-built code block at the right position.

    As a safety net, if the LLM ignored the instruction and still generated
    its own vulnerable-code block (in either supported locale), that block is
    stripped first.
    """
    if not code_section:
        return llm_output

    labels = _disclosure_labels(language)
    # Safety net: strip any LLM-generated vulnerable-code section.  Accept the
    # English alias as well so a model that disregards the Chinese template
    # cannot create a duplicate deterministic source section.
    output = re.sub(
        r'(?ims)^##\s+(?:Vulnerable Code|漏洞代码)\s*$.*?(?=^##\s|\Z)',
        '',
        llm_output,
    )

    # Insert the real code section before the localized reproduction steps.
    insertion_points = [f"## {labels['steps']}", "## Steps to Reproduce"]
    insertion_point = next((item for item in insertion_points if item in output), None)
    if insertion_point:
        output = output.replace(
            insertion_point,
            f"{code_section}\n\n{insertion_point}",
            1,
        )
    else:
        # Fallback: insert before the localized impact section.
        fallback_points = [f"## {labels['impact']}", "## Impact"]
        fallback = next((item for item in fallback_points if item in output), None)
        if fallback:
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


def _localize_disclosure_markdown(text: str, language: str = "en") -> str:
    """Translate deterministic disclosure labels without touching evidence/code.

    LLM output is still free-form, so the report layer normalizes known English
    headings/field labels when producing the Chinese variant.  Replacements
    are anchored to Markdown headings or list-label prefixes; source snippets,
    paths, function names, and model evidence remain byte-for-byte unchanged.
    """
    if _disclosure_locale(language) != "zh-CN":
        return text
    output = text or ""
    heading_map = {
        "Security Disclosure": "安全漏洞披露",
        "Vulnerable Code": "漏洞代码",
        "Evidence Context": "证据上下文",
        "Target Source Location": "目标源码位置",
        "Source-to-Sink Evidence": "源到汇证据",
        "Call Chain Source": "调用链源码",
        "Call Graph Evidence": "调用图证据",
        "Stage 2 Assessment": "第二阶段评估",
        "Summary": "摘要",
        "Steps to Reproduce": "复现步骤",
        "Impact": "影响",
        "Suggested Fix": "建议修复",
    }
    for source, target in heading_map.items():
        output = re.sub(
            rf"(?im)^(##?|###)\s+{re.escape(source)}\s*$",
            lambda match, target=target: f"{match.group(1)} {target}",
            output,
        )
    field_map = {
        "Product": "产品",
        "Type": "类型",
        "Affected": "影响版本",
        "Tested": "测试环境",
        "Function": "函数",
        "File": "文件",
        "Route key": "路由键",
        "Entry point": "入口",
        "Ordered data flow": "有序数据流",
        "Data-flow summary": "数据流摘要",
        "Attack scenario": "攻击场景",
        "Function route chain": "函数路由链",
        "Sink reached": "是否到达汇",
        "Attacker control at sink": "攻击者在汇点的控制能力",
        "Path broken at": "路径中断位置",
        "Native edges": "原生调用边",
        "Semantic edges": "语义调用边",
        "Projected/recovered edges": "投影/恢复调用边",
        "Graph statistics": "调用图统计",
        "Recovery summary": "恢复摘要",
        "Coverage note": "覆盖范围说明",
        "Defect status": "缺陷状态",
        "Reachability status": "可达性状态",
        "Impact status": "影响状态",
        "Evidence completeness": "证据完整性",
        "Boundary type": "边界类型",
        "Missing evidence": "缺失证据",
        "Assessment confidence": "评估置信度",
    }
    for source, target in field_map.items():
        # Match only bold Markdown labels (including a trailing colon) so a
        # source-code comment or an evidence value containing the same words
        # is never translated.
        output = re.sub(
            rf"(\*\*){re.escape(source)}:\s*(\*\*)",
            rf"\1{target}：\2",
            output,
        )
    output = output.replace(
        "No call-chain function source was preserved in the available artifacts.",
        "可用产物中没有保存调用链函数源码。",
    )
    output = output.replace(
        "No local graph edge connected the selected context nodes.",
        "选定的上下文节点之间没有保存本地调用图边。",
    )
    output = output.replace("Evidence artifacts:", "证据来源产物：")
    output = re.sub(
        r"(?im)^#\s+Security Disclosure\s*:\s*",
        "# 安全漏洞披露：",
        output,
        count=1,
    )
    # Normalize metadata labels emitted with either ASCII or full-width colon.
    for source, target in {
        "Product": "产品",
        "Type": "类型",
        "Affected": "影响版本",
        "Tested": "测试环境",
    }.items():
        output = re.sub(
            rf"(?im)^(\s*\*\*){re.escape(source)}\s*[:：](\*\*)",
            rf"\1{target}：\2",
            output,
        )
    for label in ("产品", "类型", "影响版本", "测试环境"):
        output = re.sub(
            rf"(?im)^(\s*\*\*){re.escape(label)}\s*[:：](\*\*)",
            rf"\1{label}：\2",
            output,
        )
    return output


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
    branch = (
        repository.get("branch")
        or repository.get("revision")
        or pipeline_data.get("branch")
        or pipeline_data.get("revision")
    )
    if branch:
        return f"Scanned source revision ({branch}; commit not recorded)"
    return "Version evidence unavailable (scanned revision not recorded)"


def _is_placeholder_fix(value) -> bool:
    """Return whether a suggested fix is prose/placeholder rather than code."""
    if not isinstance(value, str):
        return True
    text = value.strip()
    if not text:
        return True
    lowered = text.lower()
    if any(marker.lower() in lowered for marker in _REPAIR_PLACEHOLDER_MARKERS):
        return True
    # A short imperative sentence is useful as rationale, but it is not a
    # patch that can be pasted into a review.  Accept common code indicators
    # and fenced/diff snippets only as executable fix candidates.
    return not (
        "```" in text
        or "diff --git" in lowered
        or "@@" in text
        or re.search(r"\b(if|switch|return|assert|CHECK|validate|Validate)\b", text)
        and ("(" in text or ";" in text or "{" in text)
    )


def _clean_repair_code(value) -> str:
    """Extract a bounded code/diff snippet from a repair-model response."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or _is_placeholder_fix(text):
        return ""
    fenced = re.findall(r"```(?:[A-Za-z0-9_+.#-]+)?\s*\n(.*?)```", text, flags=re.DOTALL)
    if fenced:
        text = max((item.strip() for item in fenced), key=len, default="")
    if not text or _is_placeholder_fix(text):
        return ""
    return text[:MAX_REPAIR_SOURCE_CHARS]


def _repair_context_payload(vulnerability_data: Mapping) -> dict:
    """Build a bounded source/evidence payload for the repair-model call."""
    context = vulnerability_data.get("report_context")
    context = context if isinstance(context, Mapping) else {}
    target = context.get("target")
    target = target if isinstance(target, Mapping) else {}
    chain = context.get("call_chain")
    chain = chain if isinstance(chain, Mapping) else {}
    nodes = []
    for node in chain.get("nodes", []) or []:
        if not isinstance(node, Mapping):
            continue
        nodes.append({
            key: node.get(key)
            for key in ("order", "role", "function", "file", "start_line", "end_line", "reason", "source_code")
            if node.get(key) not in (None, "", [])
        })
    payload = {
        "function": vulnerability_data.get("location", {}).get("function")
        if isinstance(vulnerability_data.get("location"), Mapping) else "unknown",
        "file": vulnerability_data.get("location", {}).get("file")
        if isinstance(vulnerability_data.get("location"), Mapping) else "unknown",
        "vulnerability_categories": vulnerability_data.get("vulnerability_categories", []),
        "impact": vulnerability_data.get("impact", []),
        "reasoning": vulnerability_data.get("description") or vulnerability_data.get("reasoning"),
        "attack_scenario": vulnerability_data.get("attack_scenario"),
        "target_source": target.get("source_code") or vulnerability_data.get("vulnerable_code"),
        "source_to_sink": context.get("source_to_sink", {}),
        "call_chain": nodes,
    }
    # Keep the repair prompt bounded even if an old pipeline lacks the phase-1
    # context limits.
    encoded = json.dumps(payload, ensure_ascii=False)
    if len(encoded) <= MAX_REPAIR_CONTEXT_CHARS:
        return payload
    payload["call_chain"] = nodes[:8]
    payload["target_source"] = str(payload.get("target_source") or "")[:MAX_REPAIR_SOURCE_CHARS]
    payload["source_to_sink"] = {
        key: value for key, value in (payload.get("source_to_sink") or {}).items()
        if key in ("entry_point", "ordered_steps", "dataflow_summary", "attack_scenario", "function_route_chain")
    }
    return payload


def _parse_repair_response(text: str) -> dict:
    """Parse the repair adapter's JSON/fenced response defensively."""
    response = (text or "").strip()
    # A report adapter/test double may return an entire disclosure document
    # containing the vulnerable-code fence.  That is not a repair response and
    # must never be mistaken for a patch.
    if re.search(r"(?im)^#\s+Security Disclosure\b", response):
        return {
            "status": "unavailable",
            "code": "",
            "rationale": "修复模型未返回专用修复响应。",
            "assumptions": "",
        }
    parsed = None
    if response:
        candidates = [response]
        candidates.extend(re.findall(r"```(?:json)?\s*\n(.*?)```", response, flags=re.DOTALL))
        for candidate in candidates:
            try:
                value = json.loads(candidate.strip())
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(value, Mapping):
                parsed = value
                break
        if parsed is None:
            decoder = json.JSONDecoder()
            for match in re.finditer(r"\{", response):
                try:
                    value, _end = decoder.raw_decode(response[match.start():])
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if isinstance(value, Mapping):
                    parsed = value
                    break
    if isinstance(parsed, Mapping):
        code = _clean_repair_code(
            parsed.get("patch") or parsed.get("code") or parsed.get("fixed_code_snippet")
        )
        return {
            "status": "generated" if code else "unavailable",
            "code": code,
            "rationale": str(parsed.get("rationale") or parsed.get("explanation") or "").strip(),
            "assumptions": str(parsed.get("assumptions") or "").strip(),
        }
    code = _clean_repair_code(response)
    return {
        "status": "generated" if code else "unavailable",
        "code": code,
        "rationale": "" if code else "修复模型未返回可验证的代码片段。",
        "assumptions": "",
    }


def _generate_repair_suggestion(
    vulnerability_data: Mapping,
    binding: PhaseBinding,
) -> tuple[dict, dict]:
    """Ask the report-phase model for a minimal, evidence-backed patch."""
    provided = vulnerability_data.get("suggested_fix")
    if isinstance(provided, str) and not _is_placeholder_fix(provided):
        return {
            "status": "provided",
            "code": _clean_repair_code(provided),
            "rationale": provided if not _clean_repair_code(provided) else "扫描阶段已提供修复片段。",
            "assumptions": "",
            "reference_only": False,
        }, {
            "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
            "cost_usd": 0.0, "cost_cny": 0.0, "costs_by_currency": {},
        }

    from utilities.llm import Message, TextBlock

    payload = _repair_context_payload(vulnerability_data)
    if not payload.get("target_source"):
        return _reference_repair_info(
            vulnerability_data,
            "当前扫描产物未保存目标函数源码。",
        ), {
            "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
            "cost_usd": 0.0, "cost_cny": 0.0, "costs_by_currency": {},
        }
    prompt = load_prompt("repair")
    prompt = prompt.replace("{repair_context}", json.dumps(payload, ensure_ascii=False, indent=2))
    try:
        result = binding.adapter.complete(
            model=binding.model,
            max_tokens=2048,
            system=load_prompt("system"),
            messages=[Message(role="user", content=[TextBlock(prompt)])],
        )
        response = "\n".join(
            block.text for block in result.content if isinstance(block, TextBlock)
        )
        info = _parse_repair_response(response)
        usage = _extract_usage(
            result.input_tokens,
            result.output_tokens,
            binding.model,
            pricing=lookup_pricing(binding),
        )
        if not info.get("code"):
            # A model may honestly return manual_review or malformed output.
            # Keep the reason, but always give the reviewer an actionable
            # reference template instead of an empty repair section.
            info = _reference_repair_info(
                vulnerability_data,
                str(info.get("rationale") or "修复模型未返回可验证代码片段。"),
                str(info.get("assumptions") or ""),
            )
        return info, usage
    except Exception as exc:  # report generation must remain fail-safe
        return _reference_repair_info(
            vulnerability_data,
            f"修复模型调用失败：{type(exc).__name__}。",
        ), {
            "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
            "cost_usd": 0.0, "cost_cny": 0.0, "costs_by_currency": {},
        }


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


def _reference_repair_code(vulnerability_data: Mapping) -> str:
    """Build a conservative repair *reference* when a patch cannot be proven.

    A report must remain useful even when the repair model has no source, times
    out, or correctly refuses to invent repository-specific APIs.  This helper
    deliberately emits an insertion-level template rather than pretending to
    know the project's types and error constants.  The renderer labels it as
    reference-only and includes the target location so a maintainer can adapt
    it at the real trust boundary.
    """
    file_path, function = _finding_location(vulnerability_data)
    categories = vulnerability_data.get("vulnerability_categories") or []
    if isinstance(categories, (list, tuple, set)):
        category_text = " ".join(str(item) for item in categories)
    else:
        category_text = str(categories)
    evidence = " ".join(
        str(vulnerability_data.get(key) or "")
        for key in ("cwe_name", "description", "reasoning", "attack_scenario")
    )
    signals = f"{category_text} {evidence}".lower()
    target = f"{file_path}:{function}"
    header = (
        "/* Advisory reference template for " + target + ".\n"
        " * Replace placeholder helpers, types, and error values with the\n"
        " * repository's verified interfaces before applying or compiling.\n"
        " */"
    )

    # Prefer a sink-specific template when the evidence identifies a common
    # security boundary.  The snippets are intentionally small and do not
    # assert that an unknown helper already exists in the repository.
    if any(marker in signals for marker in (
        "command_injection", "command injection", "os_command", "cwe-78",
        "shell", "popen", "system(", "exec(", "外部命令", "命令注入",
    )):
        body = """// Validate an allowlisted operation and construct argv without a shell.
if (!IsAllowedCommand(input)) {
    return ERR_INVALID_PARAM;  // use the repository's established error value
}
std::vector<std::string> argv;
if (!BuildValidatedArgv(input, argv)) {
    return ERR_INVALID_PARAM;
}
return ExecuteWithoutShell(argv, result);  // do not concatenate input into sh -c
"""
    elif any(marker in signals for marker in (
        "null_dereference", "null pointer", "null pointer", "nullptr",
        "use_after_free", "uaf", "空指针", "悬空",
    )):
        body = """if (object == nullptr) {
    return ERR_INVALID_PARAM;  // use the repository's established error value
}
// Continue only after the lifetime/ownership precondition is established.
"""
    elif any(marker in signals for marker in (
        "resource_exhaustion", "uncontrolled resource", "ipc_input_validation",
        "out_of_bounds", "out-of-bounds", "bounds", "length", "count",
        "size", "integer", "overflow", "越界", "资源耗尽", "输入校验",
    )):
        body = """constexpr size_t kMaxItems = /* repository-specific limit */;
if (items.size() > kMaxItems) {
    return ERR_INVALID_PARAM;  // use the repository's established error value
}
for (const auto &item : items) {
    if (item == nullptr) {
        return ERR_INVALID_PARAM;
    }
}
"""
    elif any(marker in signals for marker in (
        "authz", "authorization", "permission", "access control", "权限",
        "身份校验", "越权",
    )):
        body = """if (!HasRequiredPermission(callingIdentity)) {
    return ERR_PERMISSION_DENIED;  // use the repository's real permission API/value
}
"""
    elif any(marker in signals for marker in (
        "path traversal", "path", "文件路径", "路径穿越", "directory traversal",
    )):
        body = """if (!IsPathWithinAllowedRoot(path, allowedRoot)) {
    return ERR_INVALID_PARAM;  // use the repository's established error value
}
"""
    elif any(marker in signals for marker in (
        "race", "deadlock", "concurrency", "竞态", "并发", "锁",
    )):
        body = """std::lock_guard<std::mutex> lock(stateMutex_);
// Perform the check and the state update while holding the same lock.
"""
    else:
        body = """if (!ValidateExternalInput(input)) {
    return ERR_INVALID_PARAM;  // use the repository's established error value
}
"""
    return header + "\n" + body.strip()


def _reference_repair_info(
    vulnerability_data: Mapping,
    reason: str,
    assumptions: str = "",
) -> dict:
    """Return a non-empty, explicitly non-applicable repair suggestion."""
    return {
        "status": "reference_generated",
        "code": _reference_repair_code(vulnerability_data),
        "rationale": (
            "当前证据不足以证明一份可直接应用的仓库级补丁；已生成保守的参考模板。"
            + (f" 原因：{reason}" if reason else "")
        ),
        "assumptions": assumptions or (
            "请将占位的校验函数、类型、权限接口和错误码替换为仓库真实实现，"
            "并通过编译、单元测试、回归测试及必要的安全复核。"
        ),
        "reference_only": True,
    }


def _prompt_payload(vulnerability_data: Mapping) -> dict:
    """Copy finding evidence while keeping verbatim source out of the LLM.

    Source text is rendered deterministically by ``_splice_code_section`` (and
    will be rendered for the call-chain context by the report layer).  Keeping
    it out of the model prompt prevents a disclosure model from rewriting or
    fabricating source, while still exposing locations, graph edges and the
    Stage-2 source-to-sink explanation.  The original finding object is never
    mutated.
    """
    payload = dict(vulnerability_data)
    context = payload.get("report_context")
    if not isinstance(context, Mapping):
        return payload
    context_copy = json.loads(json.dumps(context, ensure_ascii=False))
    target = context_copy.get("target")
    if isinstance(target, dict):
        target.pop("source_code", None)
    chain = context_copy.get("call_chain")
    if isinstance(chain, dict):
        for node in chain.get("nodes", []) or []:
            if isinstance(node, dict):
                node.pop("source_code", None)
    payload["report_context"] = context_copy
    return payload


def _priority_value(value, *, limit: int = 12_000) -> str:
    """Render a report claim without assuming the model returned a string."""
    if value is None:
        return ""
    if isinstance(value, str):
        text = value.strip()
    elif isinstance(value, (list, tuple)):
        text = "\n".join(
            f"- {item.strip()}" for item in value
            if isinstance(item, str) and item.strip()
        )
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            text = str(value)
    return text[:limit] + ("…[已截断]" if len(text) > limit else "")


def _call_chain_overview(context: Mapping) -> dict[str, list[list[str]]]:
    """Return all recorded strict/candidate paths for report display.

    The disclosure's attack-chain narrative intentionally uses one selected
    route. This helper exposes the complete path inventory that was preserved
    by Stage 1, without upgrading candidate edges or inventing paths. Older
    artifacts may only contain node-shaped paths, so IDs are derived from
    stable id/route_key/name fields as a fallback.
    """
    if not isinstance(context, Mapping):
        return {"strict": [], "candidate": []}

    phase_context = context.get("phase_context")
    phase_context = phase_context if isinstance(phase_context, Mapping) else {}
    stage1 = phase_context.get("stage1")
    stage1 = stage1 if isinstance(stage1, Mapping) else {}

    # Keep compatibility with reports produced before phase_context was
    # introduced, and with contexts copied directly from reachability output.
    containers = [stage1]
    if context not in containers:
        containers.append(context)
    for key in ("entry_context", "reachability_context", "stage1_context"):
        value = context.get(key)
        if isinstance(value, Mapping) and value not in containers:
            containers.append(value)

    def normalize_path(path) -> list[str]:
        if not isinstance(path, (list, tuple)):
            return []
        result = []
        for item in path:
            if isinstance(item, Mapping):
                item = item.get("id") or item.get("route_key") or item.get("name")
            if item in (None, ""):
                continue
            value = str(item).strip()
            if value:
                result.append(value)
        return result

    def collect(ids_key: str, paths_key: str) -> list[list[str]]:
        collected = []
        for container in containers:
            raw_ids = container.get(ids_key)
            if isinstance(raw_ids, list):
                for path in raw_ids:
                    normalized = normalize_path(path)
                    if normalized and normalized not in collected:
                        collected.append(normalized)
            if collected:
                # IDs are authoritative when present. Do not duplicate them
                # with corresponding node-shaped paths.
                continue
            raw_paths = container.get(paths_key)
            if isinstance(raw_paths, list):
                for path in raw_paths:
                    normalized = normalize_path(path)
                    if normalized and normalized not in collected:
                        collected.append(normalized)
        return collected

    return {
        "strict": collect("entry_path_ids", "entry_paths"),
        "candidate": collect("candidate_entry_path_ids", "candidate_entry_paths"),
    }


def _strip_markdown_section_heading(section: str) -> str:
    """Remove the leading level-2 heading from a deterministic section."""
    if not isinstance(section, str):
        return ""
    return re.sub(r"(?im)^##\s+[^\n]+\n*", "", section, count=1).strip()


def _priority_trigger_location(vulnerability_data: Mapping, context: Mapping) -> tuple[dict, str]:
    """Choose the most precise source range available for the trigger.

    Stage-1/Stage-2 records sometimes provide a finding-specific line range;
    older artifacts only carry the target function range.  The latter is
    reported explicitly instead of inventing a sink line.
    """
    target = context.get("target") if isinstance(context, Mapping) else {}
    target = target if isinstance(target, Mapping) else {}
    target_location = target.get("source_location")
    target_location = target_location if isinstance(target_location, Mapping) else {}

    candidates = [
        vulnerability_data.get("trigger_location"),
        vulnerability_data.get("evidence_location"),
    ]
    issues = vulnerability_data.get("independent_findings")
    if isinstance(issues, list):
        candidates.extend(
            item for item in issues
            if isinstance(item, Mapping) and item.get("target_match") is not False
        )
    candidates.append(vulnerability_data.get("location"))
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        start = candidate.get("line_start", candidate.get("start_line"))
        end = candidate.get("line_end", candidate.get("end_line", start))
        file_path = candidate.get("file") or candidate.get("file_path")
        function = candidate.get("function") or candidate.get("function_analyzed")
        if isinstance(start, int) and start > 0:
            return {
                "file": str(file_path or target_location.get("file") or "unknown"),
                "function": str(function or target_location.get("function") or "unknown"),
                "start_line": start,
                "end_line": end if isinstance(end, int) and end >= start else start,
            }, "finding-specific evidence range"

    return {
        "file": str(target_location.get("file") or "unknown"),
        "function": str(target_location.get("function") or "unknown"),
        "start_line": target_location.get("start_line"),
        "end_line": target_location.get("end_line"),
    }, "target function range (no finer trigger line was preserved)"


def _render_priority_disclosure_section(
    vulnerability_data: Mapping,
    code_section: str,
    context: Mapping | None,
    fix_section: str,
    *,
    locale: str = "en",
) -> str:
    """Render the reviewer-first portion of a disclosure.

    This block is deterministic for source locations, line ranges and call
    chain source.  Model prose is used only as an already-recorded claim; it
    never gets to rewrite source snippets or reorder the evidence chain.
    """
    labels = _disclosure_labels(locale)
    context = context if isinstance(context, Mapping) else {}
    target = context.get("target")
    target = target if isinstance(target, Mapping) else {}
    source_sink = context.get("source_to_sink")
    source_sink = source_sink if isinstance(source_sink, Mapping) else {}
    phase_context = context.get("phase_context")
    phase_context = phase_context if isinstance(phase_context, Mapping) else {}
    stage2_phase = phase_context.get("stage2")
    stage2_phase = stage2_phase if isinstance(stage2_phase, Mapping) else {}
    chain = context.get("call_chain")
    chain = chain if isinstance(chain, Mapping) else {}

    def line_range(location: Mapping) -> str:
        start = location.get("start_line")
        end = location.get("end_line")
        if isinstance(start, int) and isinstance(end, int):
            return f"{start}-{end}"
        if isinstance(start, int):
            return str(start)
        return "unknown"

    description = _priority_value(
        vulnerability_data.get("description")
        or vulnerability_data.get("reasoning")
        or "当前产物没有保存详细漏洞说明。"
    )
    impact = _priority_value(
        vulnerability_data.get("impact")
        or vulnerability_data.get("attack_vector")
        or "当前产物没有保存明确影响，需人工确认。"
    )
    trigger, trigger_basis = _priority_trigger_location(vulnerability_data, context)
    trigger_code = _strip_markdown_section_heading(code_section)
    if not trigger_code:
        trigger_code = "源码片段未保存在当前扫描产物中，请按文件和行号复核。"

    root_cause = _priority_value(
        vulnerability_data.get("root_cause")
        or vulnerability_data.get("guard_analysis")
        or vulnerability_data.get("reasoning")
        or "当前产物没有保存独立的根因字段。"
    )
    attack_scenario = _priority_value(
        source_sink.get("attack_scenario")
        or vulnerability_data.get("attack_scenario")
        or vulnerability_data.get("attack_vector")
    )
    entry = _priority_value(source_sink.get("entry_point"))
    route_chain = source_sink.get("function_route_chain")
    ordered_steps = source_sink.get("ordered_steps")

    lines = [f"## {labels['core']}", ""]
    lines.extend([f"### {labels['description']}", "", description, ""])
    lines.extend([f"### {labels['impact']}", "", impact, ""])
    lines.extend([f"### {labels['trigger']}", ""])
    lines.append(
        f"- **{labels['file']}:** `{trigger.get('file', 'unknown')}`"
        f"（{trigger.get('function', 'unknown')}，行 {line_range(trigger)}）"
    )
    lines.append(f"- **{labels['granularity']}:** {trigger_basis}")
    lines.extend(["", trigger_code, ""])

    lines.extend([f"### {labels['attack_chain']}", ""])
    if entry:
        lines.append(f"- **{labels['entry']}:** {entry}")
    if isinstance(route_chain, list) and route_chain:
        lines.append(f"- **{labels['route_chain']}:** `{' → '.join(str(item) for item in route_chain)}`")
    if isinstance(ordered_steps, list) and ordered_steps:
        lines.append(f"- **{labels['ordered_flow']}:**")
        for index, step in enumerate(ordered_steps, 1):
            rendered = _priority_value(step, limit=4_000)
            if rendered:
                lines.append(f"  {index}. {rendered}")
    if attack_scenario:
        lines.extend(["", f"**{labels['scenario']}:** {attack_scenario}"])
    dataflow_status = _priority_value(stage2_phase.get("parameter_dataflow_status"))
    if dataflow_status:
        lines.append(f"- **{labels['dataflow_status']}:** `{dataflow_status}`")
    for label, key in (
        (labels['sink_reached'], "sink_reached"),
        (labels['attacker_control'], "attacker_control_at_sink"),
        (labels['path_broken'], "path_broken_at"),
    ):
        value = _priority_value(source_sink.get(key))
        if value:
            lines.append(f"- **{label}:** {value}")
    if not entry and not route_chain and not ordered_steps and not attack_scenario:
        lines.append("> 当前产物没有保存从外部入口到目标函数的结构化攻击链。")

    # The narrative above intentionally follows one selected route. Keep a
    # separate deterministic inventory so reviewers can see every strict and
    # candidate path preserved by reachability, without treating candidates as
    # confirmed execution paths.
    overview = _call_chain_overview(context)
    lines.extend(["", f"### {labels['call_chain_overview']}", ""])
    overview_rendered = False
    for key, label in (
        ("strict", labels["strict_chains"]),
        ("candidate", labels["candidate_chains"]),
    ):
        paths = overview.get(key) or []
        if not paths:
            continue
        overview_rendered = True
        count_suffix = (
            f"（{len(paths)} 条）"
            if _disclosure_locale(locale) == "zh-CN"
            else f" ({len(paths)})"
        )
        lines.append(f"- **{label}{count_suffix}:**")
        for index, path in enumerate(paths, 1):
            lines.append(f"  {index}. {' → '.join(path)}")
    if not overview_rendered:
        lines.append(f"> {labels['no_call_chain_overview']}")
    else:
        lines.append(
            "> 严格路径来自已记录的结构调用图；候选路径仅作补充证据，"
            "不等同于已确认的运行时调用。"
            if _disclosure_locale(locale) == "zh-CN" else
            "> Strict paths come from the recorded structural graph; candidate "
            "paths are supplementary evidence and are not confirmed runtime calls."
        )

    lines.extend(["", f"### {labels['root_cause']}", "", root_cause, ""])
    lines.extend([f"### {labels['fix_points']}", ""])
    fix_body = _strip_markdown_section_heading(fix_section)
    lines.append(fix_body or "修复建议未保存，请结合目标函数、下游实现和调用者权限人工复核。")

    lines.extend(["", f"### {labels['call_chain']}", ""])
    nodes = chain.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        lines.append("> 可用产物中没有保存调用链函数源码。")
    else:
        # ``call_chain.nodes`` also contains bounded caller/callee neighbours
        # used as surrounding evidence.  Only the explicit source-to-sink
        # route belongs in the reviewer-facing attack-chain source bundle;
        # otherwise an unrelated neighbour would be presented as an execution
        # step.  Keep the neighbouring nodes in the later Evidence Context.
        route_chain = source_sink.get("function_route_chain")
        route_chain = route_chain if isinstance(route_chain, list) else []
        node_by_route = {}
        for node in nodes:
            if not isinstance(node, Mapping):
                continue
            node_route = node.get("route_key")
            if not isinstance(node_route, str) or not node_route:
                file_path = node.get("file")
                function_name = node.get("function")
                if file_path and function_name:
                    node_route = f"{file_path}:{function_name}"
            if isinstance(node_route, str) and node_route:
                node_by_route.setdefault(node_route, node)

        selected_nodes = []
        missing_routes = []
        if route_chain:
            for route in route_chain:
                route = str(route)
                node = node_by_route.get(route)
                if node is None:
                    missing_routes.append(route)
                else:
                    selected_nodes.append(node)
        else:
            # Legacy artifacts may not have a structured route; preserve their
            # recorded node order rather than inventing a new path.
            selected_nodes = [node for node in nodes if isinstance(node, Mapping)]

        if not selected_nodes:
            lines.append("> 结构化调用链存在，但对应函数源码未保存在当前扫描产物中。")
        for node in selected_nodes:
            if not isinstance(node, Mapping):
                continue
            order = node.get("order")
            function = str(node.get("function") or "unknown").replace("`", "'")
            file_path = str(node.get("file") or "unknown").replace("`", "'")
            role = str(node.get("role") or "context")
            node_loc = {
                "start_line": node.get("start_line"),
                "end_line": node.get("end_line"),
            }
            lines.extend([
                f"#### {(str(order) + '. ') if isinstance(order, int) else ''}{function}（{role}）",
                f"`{file_path}`（行 {line_range(node_loc)}）",
            ])
            code = node.get("source_code")
            if isinstance(code, str) and code:
                fence = fence_for_path(file_path, fallback="text")
                lines.extend(["", f"```{fence}", code, "```"])
            else:
                lines.append("\n> 该函数源码未保存在当前扫描产物中。")
        if missing_routes:
            lines.append(
                "\n> 调用链中以下函数没有对应的源码节点，未用邻接函数替代："
                + "、".join(missing_routes[:12])
            )
        if route_chain and len(selected_nodes) < len(nodes):
            lines.append("> 其余 caller/callee 邻接函数保留在后面的证据上下文中，不计入主调用链。")
    omitted = chain.get("omitted_node_count")
    if isinstance(omitted, int) and omitted:
        lines.append(f"\n> 调用链还有 {omitted} 个节点因上下文上限未展开。")
    lines.extend(["", "> 本节优先展示漏洞核心证据；源码、行号和调用链顺序由扫描产物确定性生成。"])
    return "\n".join(lines)


def _render_disclosure_context(
    vulnerability_data: Mapping,
    language: str = "text",
    locale: str = "en",
) -> str:
    """Render evidence-rich context deterministically after LLM generation.

    The model receives locations, data-flow claims and graph metadata, but not
    verbatim source.  This renderer adds the bounded source snippets and graph
    evidence to the final document without allowing the model to rewrite them.
    """
    # ``locale`` is separate from the code-fence ``language`` because the
    # deterministic evidence section is rendered for both English and Chinese
    # disclosures.  Keep the inventory labels localized here rather than
    # asking the disclosure model to reproduce them.
    labels = _disclosure_labels(locale)
    context = vulnerability_data.get("report_context")
    if not isinstance(context, Mapping):
        return ""
    target = context.get("target")
    target = target if isinstance(target, Mapping) else {}
    location = target.get("source_location")
    location = location if isinstance(location, Mapping) else {}
    source_sink = context.get("source_to_sink")
    source_sink = source_sink if isinstance(source_sink, Mapping) else {}
    chain = context.get("call_chain")
    chain = chain if isinstance(chain, Mapping) else {}
    graph = context.get("call_graph")
    graph = graph if isinstance(graph, Mapping) else {}
    provenance = context.get("provenance")
    provenance = provenance if isinstance(provenance, Mapping) else {}

    def display(value, limit: int = 4_000) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            result = value
        else:
            try:
                result = json.dumps(value, ensure_ascii=False, sort_keys=True)
            except (TypeError, ValueError):
                result = str(value)
        return result if len(result) <= limit else result[:limit] + "…[已截断]"

    def line_range(node: Mapping) -> str:
        start = node.get("start_line")
        end = node.get("end_line")
        if isinstance(start, int) and isinstance(end, int):
            return f"第 {start}-{end} 行"
        if isinstance(start, int):
            return f"第 {start} 行起"
        return "行号未知"

    lines = ["## Evidence Context", "", "### Target Source Location", ""]
    file_path = str(location.get("file") or "unknown").replace("`", "'")
    function = str(location.get("function") or "unknown").replace("`", "'")
    lines.append(f"- **Function:** `{function}`")
    lines.append(f"- **File:** `{file_path}` ({line_range(location)})")
    route = location.get("route_key") or vulnerability_data.get("route_key")
    if route:
        display_route = str(route).replace("`", "'")
        lines.append(f"- **Route key:** `{display_route}`")

    lines.extend(["", "### Source-to-Sink Evidence", ""])
    entry = display(source_sink.get("entry_point"))
    if entry:
        lines.append(f"- **Entry point:** {entry}")
    steps = source_sink.get("ordered_steps")
    if isinstance(steps, list) and steps:
        lines.append("- **Ordered data flow:**")
        for index, step in enumerate(steps, 1):
            lines.append(f"  {index}. {display(step, 2_000)}")
    for label, key in (
        ("Data-flow summary", "dataflow_summary"),
        ("Attack scenario", "attack_scenario"),
        ("Function route chain", "function_route_chain"),
    ):
        value = source_sink.get(key)
        if value not in (None, "", []):
            lines.append(f"- **{label}:** {display(value, 6_000)}")
    if "sink_reached" in source_sink:
        lines.append(f"- **Sink reached:** `{display(source_sink.get('sink_reached')) or 'unknown'}`")
    if source_sink.get("attacker_control_at_sink"):
        lines.append(f"- **Attacker control at sink:** `{display(source_sink.get('attacker_control_at_sink'))}`")
    if source_sink.get("path_broken_at"):
        lines.append(f"- **Path broken at:** {display(source_sink.get('path_broken_at'))}")

    # Stage 2 records defect, route, impact, and evidence completeness as
    # orthogonal fields.  Render them deterministically so an unresolved
    # route is visibly different from a clean verdict, even when the report
    # model's prose omits or paraphrases that distinction.
    assessment = context.get("assessment")
    if isinstance(assessment, Mapping) and assessment:
        lines.extend(["", "### Stage 2 Assessment", ""])
        assessment_labels = (
            ("Defect status", "defect_status"),
            ("Reachability status", "reachability_status"),
            ("Impact status", "impact_status"),
            ("Evidence completeness", "evidence_completeness"),
            ("Boundary type", "boundary_type"),
        )
        for label, key in assessment_labels:
            value = assessment.get(key)
            if value not in (None, "", []):
                lines.append(f"- **{label}:** `{display(value, 500)}`")
        missing = assessment.get("missing_evidence")
        if isinstance(missing, list) and missing:
            lines.append("- **Missing evidence:**")
            for item in missing[:12]:
                if item not in (None, ""):
                    lines.append(f"  - {display(item, 1_000)}")
        if assessment.get("confidence") is not None:
            lines.append(f"- **Assessment confidence:** `{display(assessment.get('confidence'), 100)}`")

    # A single target context can contain multiple independent issues.  Keep
    # the inventory visible in the disclosure artifact, but do not turn
    # context risks into separate disclosures automatically.  This is a
    # deterministic projection of the normalized Stage-1/Stage-2 records, so
    # the report cannot silently lose an alternate defect merely because the
    # LLM's narrative chose one primary issue.
    inventory = normalize_findings(
        vulnerability_data.get("independent_findings")
        or vulnerability_data.get("findings")
        or context.get("independent_findings"),
        primary_finding=(
            vulnerability_data.get("stage2_verdict")
            or vulnerability_data.get("stage1_verdict")
        ),
        synthesize_primary=True,
    )
    if inventory:
        lines.extend(["", f"### {labels['issue_inventory']}", ""])
        for index, item in enumerate(inventory[:16], 1):
            scope = str(item.get("scope") or "unknown")
            relation = str(item.get("relation") or "related")
            target_match = item.get("target_match")
            target_text = "unknown" if target_match is None else str(bool(target_match)).lower()
            issue = str(item.get("finding") or "inconclusive")
            location_file = str(item.get("file") or "unknown").replace("`", "'")
            function_name = str(
                item.get("function_analyzed") or item.get("function") or "unknown"
            ).replace("`", "'")
            start = item.get("line_start")
            end = item.get("line_end", start)
            location = f"`{location_file}:{start}-{end}`" if isinstance(start, int) else f"`{location_file}`"
            lines.append(
                f"{index}. `{issue}` · scope=`{scope}` · relation=`{relation}` "
                f"· target_match=`{target_text}` · {function_name} · {location}"
            )
            categories = item.get("vulnerability_categories")
            if categories:
                lines.append(f"   - categories: {display(categories, 1_200)}")
            impacts = item.get("impact")
            if impacts:
                lines.append(f"   - impact: {display(impacts, 1_200)}")
            reason = display(item.get("reasoning"), 2_000)
            if reason:
                lines.append(f"   - reasoning: {reason}")
            missing = item.get("missing_evidence")
            if missing:
                lines.append(f"   - missing evidence: {display(missing, 1_500)}")

    lines.extend(["", "### Call Chain Source", ""])
    nodes = chain.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        lines.append("> No call-chain function source was preserved in the available artifacts.")
    else:
        for node in nodes:
            if not isinstance(node, Mapping):
                continue
            node_function = str(node.get("function") or "unknown").replace("`", "'")
            node_file = str(node.get("file") or "unknown").replace("`", "'")
            role = str(node.get("role") or "context")
            order = node.get("order")
            prefix = f"{order}. " if isinstance(order, int) else ""
            lines.append(f"#### {prefix}{node_function} ({role})")
            lines.append(f"`{node_file}` ({line_range(node)})")
            reason = display(node.get("reason"), 1_500)
            if reason:
                lines.append(f"\n说明：{reason}")
            code = node.get("source_code")
            if isinstance(code, str) and code:
                fence = fence_for_path(node_file, fallback=language or "text")
                lines.extend(["", f"```{fence}", code, "```"])
            else:
                lines.append("\n> 该函数的源码未保存在当前扫描产物中。")
    omitted = chain.get("omitted_node_count")
    unresolved = chain.get("unresolved_references")
    if isinstance(omitted, int) and omitted:
        lines.append(f"\n> 调用链还有 {omitted} 个节点因上下文上限未展开。")
    if isinstance(unresolved, list) and unresolved:
        lines.append(f"\n> 未解析的调用引用：{display(unresolved, 4_000)}")

    lines.extend(["", "### Call Graph Evidence", ""])
    edge_count = 0
    for label, key in (
        ("Native edges", "native_edges"),
        ("Semantic edges", "semantic_edges"),
        ("Projected/recovered edges", "projected_edges"),
    ):
        edges = graph.get(key)
        if not isinstance(edges, list) or not edges:
            continue
        lines.append(f"- **{label}:**")
        for edge in edges:
            if not isinstance(edge, Mapping):
                continue
            source = str(edge.get("source") or "unknown").replace("`", "'")
            target_name = str(edge.get("target") or "unknown").replace("`", "'")
            kind = display(edge.get("kind"), 300)
            lines.append(f"  - `{source}` → `{target_name}`" + (f" ({kind})" if kind else ""))
            edge_count += 1
    statistics = graph.get("statistics")
    if isinstance(statistics, Mapping) and statistics:
        lines.append(f"- **Graph statistics:** {display(statistics, 4_000)}")
    recovery = graph.get("recovery_summary")
    if isinstance(recovery, Mapping) and recovery:
        lines.append(f"- **Recovery summary:** {display(recovery, 4_000)}")
    coverage_note = display(graph.get("coverage_note"), 3_000)
    if coverage_note:
        lines.append(f"- **Coverage note:** {coverage_note}")
    if edge_count == 0:
        lines.append("> No local graph edge connected the selected context nodes.")

    artifacts = provenance.get("artifacts")
    if isinstance(artifacts, list) and artifacts:
        lines.extend(["", f"证据来源产物：{display(artifacts, 2_000)}"])
    lines.extend([
        "",
        "> 本节由扫描产物确定性生成，源码和行号未经过大模型改写；缺失内容表示扫描时没有保存对应证据。",
    ])
    return "\n".join(lines)


def _render_repair_section(
    vulnerability_data: Mapping,
    repair_info: Mapping,
    language: str,
    locale: str = "en",
) -> str:
    """Render a deterministic Suggested Fix section from repair evidence."""
    status = str(repair_info.get("status") or "unavailable")
    code = repair_info.get("code")
    code = code if isinstance(code, str) else ""
    rationale = str(repair_info.get("rationale") or "").strip()
    assumptions = str(repair_info.get("assumptions") or "").strip()
    file_path, function = _finding_location(vulnerability_data)
    lines = [f"## {_disclosure_labels(locale)['fix']}", ""]
    # The report contract requires a code example even when the evidence is
    # insufficient for a repository-specific patch.  This is a final safety
    # net for historical artifacts or custom callers that bypass
    # _generate_repair_suggestion().
    reference_only = bool(repair_info.get("reference_only")) or status == "reference_generated"
    if not code:
        code = _reference_repair_code(vulnerability_data)
        status = "reference_generated"
        reference_only = True
        rationale = rationale or "未获得足够证据生成仓库专用补丁，已提供通用修复参考模板。"
        assumptions = assumptions or (
            "该片段不是可直接应用的补丁；请维护者替换占位 API、类型和错误码并完成编译验证。"
        )
    if code:
        if reference_only:
            lines.append(
                "以下是基于漏洞类别生成的修复参考模板（不是可直接应用的补丁），"
                "用于给维护者提供改动方向；提交前必须结合真实源码适配并通过编译和回归测试："
            )
        else:
            lines.append(
                "以下是基于当前源码和证据生成的候选修复片段（仍需人工适配、编译和回归测试）："
            )
        lines.extend(["", f"```{language or 'text'}", code, "```"])
        if rationale:
            lines.extend(["", f"修复说明：{rationale}"])
    if assumptions:
        lines.extend(["", f"前置假设：{assumptions}"])
    if reference_only:
        lines.extend([
            "",
            f"适用目标：`{file_path}:{function}`。模板中的校验函数、权限接口、类型和错误码均需替换为仓库真实定义。",
            "该代码仅作为修复建议参考，不代表漏洞已被修复，也不保证可编译或覆盖全部调用路径。",
        ])
    lines.extend(["", f"修复状态：`{status}`"])
    return "\n".join(lines)


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


def _scan_source_path(scan_dir: Path) -> str:
    """Find the source checkout recorded by a scan report, if any."""
    candidates: list[str] = []
    for name in ("scan.report.json", "parse.report.json", "source_handoff.json"):
        candidate = scan_dir / name
        try:
            payload = read_json(candidate) if candidate.is_file() else None
        except (OSError, ValueError, json.JSONDecodeError):
            payload = None
        if not isinstance(payload, Mapping):
            continue
        inputs = payload.get("inputs")
        outputs = payload.get("outputs")
        for container in (inputs, payload, outputs):
            if not isinstance(container, Mapping):
                continue
            for key in ("repo_path", "repository_path", "source_path", "local_path"):
                value = container.get(key)
                if isinstance(value, str) and value:
                    if value not in candidates:
                        candidates.append(value)
    # ``scan.report.json`` often records the scan-output directory itself while
    # ``parse.report.json`` records the actual source checkout.  Prefer a path
    # that is demonstrably a Git work tree instead of returning the first path.
    for value in candidates:
        try:
            candidate = Path(value).expanduser().resolve()
            if candidate.is_dir() and (candidate / ".git").exists():
                return str(candidate)
        except (OSError, RuntimeError):
            continue
    return candidates[0] if candidates else ""


def _git_revision_metadata(repo_path: str) -> dict[str, str]:
    """Read branch/commit/describe from a checkout using non-shell Git calls."""
    if not isinstance(repo_path, str) or not repo_path:
        return {}
    try:
        path = Path(repo_path).expanduser().resolve()
    except (OSError, RuntimeError):
        return {}
    if not path.is_dir():
        return {}
    # Git is invoked with a fixed argument vector and a sanitized config so a
    # repository cannot inject shell commands or aliases into this read-only
    # metadata lookup.
    env = os.environ.copy()
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "LC_ALL": "C",
    })

    def run(*args: str) -> str:
        try:
            completed = subprocess.run(
                ["git", "-C", str(path), *args],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                env=env,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if completed.returncode != 0:
            return ""
        return (completed.stdout or "").strip()

    metadata = {}
    branch = run("rev-parse", "--abbrev-ref", "HEAD")
    commit = run("rev-parse", "HEAD")
    describe = run("describe", "--tags", "--always")
    if branch and branch != "HEAD":
        metadata["branch"] = branch
    if commit and re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
        metadata["commit_sha"] = commit
    if describe and len(describe) <= 256:
        metadata["release_version"] = describe
    if metadata.get("branch") or metadata.get("commit_sha"):
        metadata["source"] = "git"
    return metadata


def _hydrate_revision_metadata(pipeline_path: str, pipeline_data: dict) -> None:
    """Fill missing revision fields from the checkout recorded by the scan."""
    repository = pipeline_data.get("repository")
    if not isinstance(repository, dict):
        return
    if repository.get("commit_sha") and repository.get("release_version"):
        return
    scan_dir = Path(pipeline_path).resolve().parent
    source_path = _scan_source_path(scan_dir)
    metadata = _git_revision_metadata(source_path)
    if not metadata:
        return
    for key in ("commit_sha", "branch", "release_version"):
        if metadata.get(key) and not repository.get(key):
            repository[key] = metadata[key]
    provenance = pipeline_data.setdefault("revision_provenance", {})
    if isinstance(provenance, dict):
        provenance.update({
            "source": metadata.get("source", "git"),
            "source_path_recorded": bool(source_path),
        })


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

    _hydrate_revision_metadata(pipeline_path, pipeline_data)
    scan_dir = Path(pipeline_path).resolve().parent
    source_map = {}
    result_by_route = {}
    for name in ("results_verified.json", "results.json", "call_graph.json"):
        candidate = scan_dir / name
        try:
            if candidate.is_file():
                payload = read_json(candidate)
                recovered = _artifact_code_by_route(payload)
                for route, code in recovered.items():
                    source_map.setdefault(route, code)
                if name in ("results_verified.json", "results.json") and isinstance(payload, Mapping):
                    for result in payload.get("results", []) or []:
                        if not isinstance(result, Mapping):
                            continue
                        route = result.get("route_key") or result.get("unit_id")
                        if isinstance(route, str) and route:
                            result_by_route.setdefault(route, result)
        except (OSError, ValueError, json.JSONDecodeError):
            continue

    # Newer pipeline files already carry this context.  For historical files,
    # rebuild it from sibling artifacts in memory so report regeneration gains
    # exact line ranges, source-to-sink evidence, and graph edges without
    # rewriting the original scan output.
    context_index = load_report_context_index(scan_dir)

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
        route = str(finding.get("route_key") or f"{file_path}:{function}")
        code = finding.get("vulnerable_code") or source_map.get(route)
        if isinstance(code, str) and code:
            finding["vulnerable_code"] = code
        if isinstance(code, str) and code and not finding.get("vulnerable_code_section"):
            fence = fence_for_path(file_path, fallback=language or "text")
            finding["vulnerable_code_section"] = (
                "## Vulnerable Code\n\n"
                f"`{file_path}`:\n\n"
                f"```{fence}\n{code}\n```"
            )

        if not finding.get("route_key"):
            finding["route_key"] = route
        if not finding.get("report_context"):
            full_result = result_by_route.get(route, finding)
            context = build_disclosure_context(
                context_index,
                route,
                finding=finding,
                full_result=full_result,
                source_code=code if isinstance(code, str) else "",
            )
            finding["report_context"] = context
            location = context.get("target", {}).get("source_location", {})
            if isinstance(location, Mapping):
                # Preserve the historical file/function fields while adding
                # exact source lines when the graph/dataset knows them.
                finding_location = finding.setdefault("location", {})
                if isinstance(finding_location, dict):
                    for key in ("start_line", "end_line"):
                        if finding_location.get(key) is None and location.get(key) is not None:
                            finding_location[key] = location[key]
    return pipeline_data


def _fallback_code_section(vulnerability_data: Mapping, language: str = "en") -> str:
    """Keep the disclosure schema complete when source evidence is absent."""
    file_path, function = _finding_location(vulnerability_data)
    if _disclosure_locale(language) == "zh-CN":
        return (
            "## 漏洞代码\n\n"
            f"`{file_path}` / `{function}`\n\n"
            "> 当前扫描产物未保存源码，请维护者在仓库中复核该函数。"
        )
    return (
        "## Vulnerable Code\n\n"
        f"`{file_path}` / `{function}`\n\n"
        "> Source code was not preserved in the available scan artifacts. "
        "Review the referenced function in the repository before disclosure."
    )


def _heading_present(text: str, heading: str, aliases: tuple[str, ...] = ()) -> bool:
    names = (heading, *aliases)
    pattern = "|".join(re.escape(name) for name in names)
    return bool(re.search(rf"(?im)^##\s+(?:{pattern})\s*$", text or ""))


def _ensure_disclosure_sections(
    text: str,
    vulnerability_data: Mapping,
    metadata: Mapping,
    code_section: str,
    context_section: str = "",
    fix_section: str = "",
    priority_section: str = "",
    language: str = "en",
) -> str:
    """Fill mandatory report fields the LLM omitted or left as placeholders.

    LLM output remains the narrative source, but the report contract is
    enforced deterministically.  This prevents a short/early model response
    from yielding a file that is syntactically present yet unusable to a
    reviewer.
    """
    locale = _disclosure_locale(language)
    labels = _disclosure_labels(locale)
    output = _localize_disclosure_markdown((text or "").strip(), locale)
    title = _disclosure_title(vulnerability_data)
    if not output:
        output = f"# {labels['title']}: {title}"

    # Ensure the three metadata lines are visible even if the model omitted
    # the requested header.  Insert them after the first title when possible.
    colon = "：" if locale == "zh-CN" else ":"
    metadata_lines = {
        f"**{labels['product']}{colon}**":
            f"**{labels['product']}{colon}** {metadata.get('product_name') or 'unknown'}",
        f"**{labels['type']}{colon}**": (
            f"**{labels['type']}{colon}** CWE-{vulnerability_data.get('cwe_id') or 0} "
            f"({vulnerability_data.get('cwe_name') or 'Unknown'})"
        ),
        f"**{labels['affected']}{colon}**":
            f"**{labels['affected']}{colon}** {metadata.get('affected_versions')}",
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

    if locale == "zh-CN":
        fallbacks = {
            labels["summary"]: str(vulnerability_data.get("description") or (
                "分析在报告函数中发现与安全相关的缺陷；请在复核中确认具体行为。"
            )),
            labels["steps"]: str(vulnerability_data.get("steps_to_reproduce") or (
                "[需要动态验证] 使用受控的本地测试程序复现调用，并记录输入、调用者身份和结果。"
            )),
            labels["impact"]: str(vulnerability_data.get("impact") or (
                "当前分析字段未提供影响信息，请人工确认受影响的操作。"
            )),
            labels["fix"]: str(vulnerability_data.get("suggested_fix") or (
                _reference_repair_code(vulnerability_data)
            )),
        }
    else:
        fallbacks = {
            labels["summary"]: str(vulnerability_data.get("description") or (
                "The analysis identified a security-relevant condition in the "
                "reported function; confirm the exact behavior during review."
            )),
            labels["steps"]: str(vulnerability_data.get("steps_to_reproduce") or (
                "[REQUIRES DYNAMIC TESTING] Reproduce the call with a controlled "
                "local harness and record the input, caller identity, and result."
            )),
            labels["impact"]: str(vulnerability_data.get("impact") or (
                "Impact is not available from the supplied analysis fields; confirm "
                "the affected operation manually."
            )),
            labels["fix"]: str(vulnerability_data.get("suggested_fix") or (
                _reference_repair_code(vulnerability_data)
            )),
        }

    tested_line = (
        f"**{labels['tested']}{colon}** "
        f"{metadata.get('platform_version') or 'application platform'}, "
        f"{metadata.get('analysis_date') or 'date not recorded'}."
    )
    tested_match = re.search(
        rf"(?im)^\*\*{re.escape(labels['tested'])}{re.escape(colon)}\*\*.*$",
        output,
    )
    if tested_match:
        if re.search(r"\[(?:NOT PROVIDED|REQUIRES MANUAL INPUT)\]", tested_match.group(0), re.I):
            output = output[:tested_match.start()] + tested_line + output[tested_match.end():]
    else:
        # The Tested line is part of the disclosure contract even though it is
        # not a level-2 section.  Add it next to the affected metadata.
        affected_line = metadata_lines[f"**{labels['affected']}{colon}**"]
        output = output.replace(affected_line,
                                affected_line + "\n" + tested_line,
                                1)

    # Keep the source section ahead of the reproduction steps.  It is already
    # deterministic and may contain a verbatim parser snippet.
    if not _heading_present(output, labels["code"], aliases=("Vulnerable Code", "漏洞代码")):
        insertion = "\n\n" + (code_section or _fallback_code_section(vulnerability_data))
        marker = f"## {labels['steps']}"
        if marker in output:
            output = output.replace(marker, insertion + "\n\n" + marker, 1)
        else:
            output += insertion

    for heading, fallback in fallbacks.items():
        heading_aliases = {
            labels["summary"]: ("Summary", "摘要"),
            labels["steps"]: ("Steps to Reproduce", "复现步骤"),
            labels["impact"]: ("Impact", "影响"),
            labels["fix"]: ("Suggested Fix", "建议修复"),
        }.get(heading, ())
        pattern = "|".join(re.escape(item) for item in (heading, *heading_aliases))
        heading_match = re.search(rf"(?ims)^##\s+(?:{pattern})\s*$.*?(?=^##\s|^---\s*$|\Z)", output)
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

    deterministic_sections = []

    # Context is deterministic evidence, just like Vulnerable Code.  Strip a
    # model-generated copy before appending ours so a short/verbose response
    # cannot duplicate or rewrite line numbers and graph edges.
    if context_section:
        output = re.sub(
            r"(?ims)^##\s+(?:Evidence Context|证据上下文)\s*$.*?(?=^##\s|\Z)",
            "",
            output,
        ).rstrip()
        deterministic_sections.append(context_section.strip())

    if fix_section:
        output = re.sub(
            rf"(?ims)^##\s+(?:Suggested Fix|建议修复)\s*$.*?(?=^##\s|^---\s*$|\Z)",
            "",
            output,
        ).rstrip()
        deterministic_sections.append(fix_section.strip())

    if deterministic_sections:
        insertion = "\n\n".join(deterministic_sections)
        separator = re.search(r"(?m)^---\s*$", output)
        if separator:
            output = output[:separator.start()].rstrip() + "\n\n" + insertion + "\n\n" + output[separator.start():]
        else:
            output += "\n\n" + insertion

    # Put the reviewer-first evidence block immediately after the title.  The
    # original metadata, verification state and historical narrative therefore
    # remain available below it, while the high-value description, trigger
    # range, attack chain, root cause, fix and ordered source bundle are shown
    # before those auxiliary fields.
    if priority_section:
        priority_section = priority_section.strip()
        # A model may echo the deterministic block. Remove that copy before
        # inserting the artifact-backed one, so a report never has two
        # independently rendered core sections.
        output = re.sub(
            r"(?ims)^##\s+(?:Core Vulnerability Evidence|漏洞核心证据)\s*$.*?(?=^##\s|\Z)",
            "",
            output,
        ).rstrip()
        title_match = re.search(r"(?m)^#\s+.+$", output)
        if title_match:
            pos = title_match.end()
            output = (
                output[:pos].rstrip()
                + "\n\n"
                + priority_section
                + "\n\n"
                + output[pos:].lstrip()
            )
        else:
            output = output.rstrip() + "\n\n" + priority_section

    return output.strip() + "\n"


def generate_disclosure(
    vulnerability_data: dict,
    product_name: str,
    binding: PhaseBinding,
    pipeline_data: Mapping | None = None,
    language: str = "en",
) -> tuple[str, dict]:
    """Generate a disclosure document for a single vulnerability.

    Args:
        vulnerability_data: Finding to disclose.
        product_name: Repository / product name.
        binding: Phase binding for the report phase.
        pipeline_data: Optional pipeline output carrying platform provenance.
        language: Disclosure locale (``en`` or ``zh-CN``). English is the
            backward-compatible default.

    Returns:
        (disclosure_text, usage_dict)
    """
    from utilities.llm import Message, TextBlock

    locale = _disclosure_locale(language)
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
        code_section = _fallback_code_section(vulnerability_data, locale)
    else:
        code_section = _localize_disclosure_markdown(code_section, locale)
    repair_info, repair_usage = _generate_repair_suggestion(vulnerability_data, binding)
    effective_data = dict(vulnerability_data)
    if repair_info.get("code"):
        effective_data["suggested_fix"] = repair_info["code"]
    elif repair_info.get("rationale"):
        effective_data["suggested_fix"] = repair_info["rationale"]
    payload = _prompt_payload({
        k: v for k, v in effective_data.items()
        if k not in ("vulnerable_code_section", "vulnerable_code")
    })
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
        "preconditions": str(
            vulnerability_data.get("preconditions")
            or "调用者身份、设备状态和其他前置条件请以扫描证据为准。"
        ),
        # _generate_repair_suggestion() normally supplies this code.  Keep a
        # deterministic fallback here as well so a custom repair adapter or a
        # legacy caller can never leave the disclosure prompt without code.
        "fixed_code_snippet": repair_info.get("code") or _reference_repair_code(vulnerability_data),
    }
    prompt_name = "disclosure.zh-CN" if locale == "zh-CN" else "disclosure"
    user_prompt = load_prompt(prompt_name)
    user_prompt = user_prompt.replace(
        "{vulnerability_data}", json.dumps(payload, ensure_ascii=False, indent=2), 1
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
    final_output = _splice_code_section(llm_output, code_section, locale)
    context_section = _render_disclosure_context(
        vulnerability_data,
        language=replacements["language"],
        locale=locale,
    )
    context_section = _localize_disclosure_markdown(context_section, locale)
    fix_section = _render_repair_section(
        effective_data,
        repair_info,
        replacements["language"],
        locale=locale,
    )
    priority_section = _render_priority_disclosure_section(
        effective_data,
        code_section,
        vulnerability_data.get("report_context"),
        fix_section,
        locale=locale,
    )
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
        context_section=context_section,
        fix_section=fix_section,
        priority_section=priority_section,
        language=locale,
    )

    disclosure_usage = _extract_usage(
        result.input_tokens,
        result.output_tokens,
        binding.model,
        pricing=lookup_pricing(binding),
    )
    return final_output, _merge_usage([repair_usage, disclosure_usage])


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
    disclosures_zh_dir = output_path / "disclosures.zh-CN"

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

        print(f"Generating Chinese disclosure for {finding['short_name']}...")
        disclosure_zh, _usage = generate_disclosure(
            finding,
            product_name,
            report_binding,
            pipeline_data=pipeline_data,
            language="zh-CN",
        )
        disclosures_zh_dir.mkdir(exist_ok=True)
        with open_utf8(disclosures_zh_dir / filename, "w") as f:
            f.write(disclosure_zh)
        print(f"  -> {disclosures_zh_dir / filename}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python generator.py <pipeline_output.json> <output_dir>")
        sys.exit(1)

    generate_all(sys.argv[1], sys.argv[2])
    print("Done.")
