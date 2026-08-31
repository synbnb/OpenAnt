"""Guarded LLM protocol for OpenHarmony indirect-call recovery.

This module is deliberately an *advisory* boundary for the first LLM-assisted
call-graph stage.  It selects residual call sites, builds a bounded source
context, parses a strict JSON response, and validates proposed edges against
the extracted function index.  It does not mutate ``call_graph.json`` or
``SemanticGraph``.  A later stage may project only the validated proposals.

The LLM is never asked to invent an arbitrary function.  The prompt includes
an explicitly labelled, bounded retrieval shortlist; every accepted proposal
must name an existing function id and carry call-site plus target/registration
source evidence.  Ambiguous or low-confidence proposals remain review items.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from prompts._fence import safe_code_fence

from .registration_context import (
    DEFAULT_MAX_CONTEXT_CHARS,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    build_registration_context,
)
from .evidence_line_resolver import (
    normalize_recovery_evidence,
    summarize_line_resolution,
)


RECOVERY_SCHEMA_VERSION = 1
RECOVERY_TASK = "openharmony_call_edge_recovery"
DEFAULT_MAX_SITES = 50
DEFAULT_MAX_SHORTLIST = 12
DEFAULT_MAX_CODE_BYTES = 2_000
DEFAULT_REGISTRATION_CONTEXT_MAX_FILES = DEFAULT_MAX_FILES
DEFAULT_REGISTRATION_CONTEXT_MAX_FILE_BYTES = DEFAULT_MAX_FILE_BYTES
DEFAULT_REGISTRATION_CONTEXT_MAX_CHARS = min(DEFAULT_MAX_CONTEXT_CHARS, 6_000)
_VALID_SOURCES = {"native", "lambda"}
_VALID_DECISIONS = {"add_edge", "keep_unresolved"}
_VALID_CONFIDENCES = {"high", "medium", "low"}
_VALID_EVIDENCE_KINDS = {"call_site", "registration", "target", "type"}
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
_CLASSIFICATION_RANK = {
    "unknown_indirect": 0,
    "local_dispatch": 1,
    "template_dispatch": 2,
    "external_callback": 3,
    "external_interface": 4,
    "external_dynamic_symbol": 5,
}
_BOUNDARY_MARKERS = (
    "parcel",
    "binder",
    "ipc",
    "socket",
    "recv",
    "accept",
    "command",
    "request",
    "remote",
    "message",
    "systemability",
    "system_ability",
    "samgr",
    "common_event",
    "commonevent",
    "onreceiveevent",
    "getaction",
    "getstringparam",
    "getintparam",
    "json",
    "dlsym",
    "dlopen",
    "hdi::",
    "ril",
    "minidump",
    "memoryreader",
    "faultlog",
)
_EXTERNAL_DYNAMIC_MARKERS = (
    "dlsym(",
    "dlopen(",
    "loadlibrary(",
    "getprocaddress(",
)
_EXTERNAL_INTERFACE_MARKERS = (
    "hdi::",
    "rilinterface",
    "iril",
)
_EXTERNAL_CALLBACK_MARKERS = (
    "taihe::callback",
    "callback_view",
    "safejscallback",
    "jscallback",
    "reinterpret_pointer_cast",
    "napi_",
    "ffi::",
    "arkui",
)
_COMMON_IDENTIFIER_TOKENS = {
    "this",
    "second",
    "first",
    "get",
    "set",
    "find",
    "call",
    "func",
    "function",
    "handler",
}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _function_code(function: Mapping[str, Any]) -> str:
    code = function.get("code", "")
    if isinstance(code, Mapping):
        return _text(code.get("primary_code") or code.get("source"))
    return _text(code)


def _leaf(name: Any) -> str:
    return _text(name).rsplit("::", 1)[-1].rsplit(".", 1)[-1]


def _owner(function: Mapping[str, Any]) -> str:
    explicit = _text(function.get("class_name") or function.get("className"))
    if explicit:
        return _leaf(explicit)
    name = _text(function.get("name"))
    return name.rsplit("::", 1)[-2] if "::" in name else ""


def _normalize_functions(functions: Any) -> dict[str, Mapping[str, Any]]:
    if isinstance(functions, Mapping) and isinstance(functions.get("functions"), Mapping):
        functions = functions["functions"]
    if not isinstance(functions, Mapping):
        return {}
    return {
        _text(function_id): function
        for function_id, function in functions.items()
        if _text(function_id) and isinstance(function, Mapping)
    }


def _trim_code(code: str, max_bytes: int) -> str:
    if len(code) <= max_bytes:
        return code
    return code[: max(0, max_bytes - 20)] + "\n...[truncated]"


def _line(value: Any, default: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, parsed)


def _project_function(
    function_id: str,
    function: Mapping[str, Any],
    *,
    max_code_bytes: int,
) -> dict[str, Any]:
    return {
        "function_id": function_id,
        "name": _text(function.get("name")) or function_id,
        "file_path": _text(function.get("file_path") or function.get("filePath")),
        "start_line": _line(function.get("start_line", function.get("startLine", 1))),
        "end_line": _line(function.get("end_line", function.get("endLine", 1))),
        "class_name": _owner(function),
        "parameters": function.get("parameters", []),
        "code": _trim_code(_function_code(function), max_code_bytes),
    }


def _site_context(site: Mapping[str, Any], caller: Mapping[str, Any]) -> str:
    """Return source-backed text used for conservative residual classification."""
    symbols = site.get("symbols")
    symbol_text = " ".join(
        _text(value)
        for value in symbols.values()
    ) if isinstance(symbols, Mapping) else ""
    return " ".join(
        (
            _text(site.get("file")),
            _text(site.get("expression")),
            _text(site.get("reason")),
            symbol_text,
            _text(caller.get("name")),
            _text(caller.get("file_path") or caller.get("filePath")),
            _function_code(caller),
        )
    ).lower()


def classify_recovery_site(
    site: Mapping[str, Any], caller: Mapping[str, Any]
) -> dict[str, Any]:
    """Classify an unresolved site before any LLM request is considered.

    The classification deliberately describes the *analysis route*, not a
    guessed callee.  Local dispatch and template sites should first go through
    deterministic registration/argument propagation.  Taihe/FFI callbacks,
    HDI interfaces and dynamic symbols cross the repository boundary and are
    represented as external nodes.  Only genuinely unknown in-repository
    indirection is LLM eligible.
    """
    context = _site_context(site, caller)
    expression = _text(site.get("expression")).lower()
    reason = _text(site.get("reason")).lower()
    symbols = site.get("symbols")
    dispatch_table = (
        _text(symbols.get("dispatch_table")).lower()
        if isinstance(symbols, Mapping)
        else ""
    )

    # Prefer signals on the unresolved expression itself.  The caller code in
    # a dataset unit may include inlined neighbouring functions; a stray
    # ``find``/``dlsym`` in that context must not reclassify a direct map or
    # member-pointer expression.
    lookup_expression = bool(
        re.search(r"(?:->|\.)second\s*\(", expression)
        or dispatch_table
    )
    if lookup_expression or re.search(
        r"\b(?:callback|handler|request)\w*iter\b", expression
    ):
        return {
            "kind": "local_dispatch",
            "analysis_route": "deterministic",
            "llm_eligible": False,
            "confidence": "high",
            "reason": "the expression reads a callable from a local map, table, or queue",
        }

    direct_interface_expression = any(
        marker in expression for marker in ("hdi::", "rilinterface")
    )
    if direct_interface_expression:
        return {
            "kind": "external_interface",
            "analysis_route": "external_boundary",
            "llm_eligible": False,
            "confidence": "high",
            "reason": "the receiver or interface belongs to an external HDI/RIL boundary",
        }

    template_expression = bool(
        "->*" in expression
        or "member_function_pointer" in reason
        or re.search(r"\b(?:_func|_modulefunc|getter|setter)\b", expression)
        or "template<" in context
        or "std::forward" in context
    )
    if template_expression:
        return {
            "kind": "template_dispatch",
            "analysis_route": "deterministic",
            "llm_eligible": False,
            "confidence": "medium",
            "reason": "the call target is passed through a typed member-function template",
        }

    if any(marker in context for marker in _EXTERNAL_DYNAMIC_MARKERS):
        return {
            "kind": "external_dynamic_symbol",
            "analysis_route": "external_boundary",
            "llm_eligible": False,
            "confidence": "high",
            "reason": "the call target is obtained from a dynamic-library symbol",
        }

    if any(marker in context for marker in _EXTERNAL_INTERFACE_MARKERS):
        return {
            "kind": "external_interface",
            "analysis_route": "external_boundary",
            "llm_eligible": False,
            "confidence": "high",
            "reason": "the receiver or interface belongs to an external HDI/RIL boundary",
        }

    if any(marker in context for marker in _EXTERNAL_CALLBACK_MARKERS):
        return {
            "kind": "external_callback",
            "analysis_route": "external_boundary",
            "llm_eligible": False,
            "confidence": "high",
            "reason": "the callable is supplied by a Taihe, JS, FFI, or native callback boundary",
        }

    return {
        "kind": "unknown_indirect",
        "analysis_route": "llm_review",
        "llm_eligible": True,
        "confidence": "low",
        "reason": "no local registration or external-boundary signal was found",
    }


def _site_id(
    source: str,
    caller_id: str,
    line: Any,
    expression: str,
    *,
    file_path: str = "",
    reason: str = "",
    dispatch_table: str = "",
) -> str:
    # The source span is the identity.  ``caller_id`` is only a fallback for
    # diagnostics that do not carry a file path; namespace wrapper entries
    # sharing the same span therefore collapse to one work item.  ``reason``
    # and ``dispatch_table`` are evidence fields, not identity fields: two
    # parser passes can report the same span with different metadata.
    stable_file = file_path or caller_id
    stable = "|".join((source, stable_file, str(line), expression))
    digest = hashlib.sha1(stable.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{source}:{_line(line)}:{digest}"


def _site_priority(
    site: Mapping[str, Any],
    caller: Mapping[str, Any],
    entry_point_ids: set[str],
) -> tuple[str, bool, str]:
    caller_id = _text(site.get("caller_id"))
    if caller_id in entry_point_ids or caller.get("is_entry_point") is True:
        return "high", True, "known_entry_point"
    if _leaf(caller.get("name")) == "OnRemoteRequest":
        return "high", True, "openharmony_ipc_boundary"
    haystack = _site_context(site, caller)
    if any(marker in haystack for marker in _BOUNDARY_MARKERS):
        return "medium", True, "boundary_keyword_signal"
    return "normal", False, "indirect_call_without_boundary_signal"


def _identifier_tokens(text: str) -> set[str]:
    tokens = {token.lower() for token in re.findall(r"[A-Za-z_]\w*", text)}
    return {
        token
        for token in tokens
        if len(token) >= 3 and token not in _COMMON_IDENTIFIER_TOKENS
    }


def _shortlist_functions(
    site: Mapping[str, Any],
    caller: Mapping[str, Any],
    functions: Mapping[str, Mapping[str, Any]],
    *,
    max_items: int,
    max_code_bytes: int,
    required_function_ids: Iterable[str] = (),
) -> list[dict[str, Any]]:
    caller_file = _text(caller.get("file_path") or caller.get("filePath"))
    caller_owner = _owner(caller)
    symbols = site.get("symbols")
    target_variable = (
        _text(symbols.get("target_variable"))
        if isinstance(symbols, Mapping)
        else ""
    )
    tokens = _identifier_tokens(
        " ".join((_text(site.get("expression")), target_variable))
    )
    ranked: list[tuple[int, str, Mapping[str, Any]]] = []
    for function_id, function in functions.items():
        if function_id == _text(site.get("caller_id")):
            continue
        owner = _owner(function)
        file_path = _text(function.get("file_path") or function.get("filePath"))
        name = _text(function.get("name"))
        if caller_owner and owner and caller_owner != owner:
            continue
        score = 0
        if caller_file and file_path == caller_file:
            score += 3
        if caller_owner and owner == caller_owner:
            score += 2
        lower_name = name.lower()
        score += sum(2 for token in tokens if token in lower_name)
        if score:
            ranked.append((score, function_id, function))
    ranked.sort(key=lambda item: (-item[0], item[1]))

    # Candidate-bearing sites need a different bound from ordinary retrieval.
    # ``max_items`` limits speculative context, but dropping a parser-provided
    # candidate would make the model unable to review that edge and would
    # contradict the prompt's "only propose a retrieval candidate" rule.  Keep
    # every known required target, then fill the remaining slots with the
    # ordinary ranked shortlist.  Candidate counts are parser-bounded upstream
    # and the full prompt size is still protected by the code-byte cap.
    required = sorted({
        _text(function_id)
        for function_id in required_function_ids
        if _text(function_id) in functions
        and _text(function_id) != _text(site.get("caller_id"))
    })
    required_set = set(required)
    projected: list[dict[str, Any]] = [
        _project_function(
            function_id,
            functions[function_id],
            max_code_bytes=max_code_bytes,
        )
        for function_id in required
    ]
    remaining = [item for item in ranked if item[1] not in required_set]
    remaining_limit = max(0, max_items - len(projected))
    projected.extend(
        _project_function(function_id, function, max_code_bytes=max_code_bytes)
        for _score, function_id, function in remaining[:remaining_limit]
    )
    return projected


def _raw_sites(diagnostics: Mapping[str, Any]) -> Iterable[tuple[str, Mapping[str, Any]]]:
    sites = diagnostics.get("unresolved_call_sites", [])
    if isinstance(sites, list):
        for site in sites:
            if isinstance(site, Mapping):
                yield "native", site
    lambda_payload = diagnostics.get("lambda_dispatch")
    lambda_sites = (
        lambda_payload.get("call_sites", [])
        if isinstance(lambda_payload, Mapping)
        else []
    )
    if isinstance(lambda_sites, list):
        for site in lambda_sites:
            if isinstance(site, Mapping):
                yield "lambda", site


def _raw_site_key(
    source: str,
    site: Mapping[str, Any],
    caller: Mapping[str, Any],
) -> tuple[str, str, int, str]:
    """Return the stable source-span key used to collapse parser duplicates."""
    file_path = _text(site.get("file")) or _text(
        caller.get("file_path") or caller.get("filePath")
    )
    return (
        source,
        file_path,
        _line(site.get("line")),
        _text(site.get("expression")),
    )


def _merge_classification(
    current: Mapping[str, Any] | None,
    candidate: Mapping[str, Any],
) -> dict[str, Any]:
    if current is None:
        return dict(candidate)
    current_rank = _CLASSIFICATION_RANK.get(_text(current.get("kind")), 0)
    candidate_rank = _CLASSIFICATION_RANK.get(_text(candidate.get("kind")), 0)
    return dict(candidate if candidate_rank > current_rank else current)


def _merge_symbols(
    current: Mapping[str, Any], candidate: Mapping[str, Any]
) -> dict[str, Any]:
    """Merge parser evidence without making duplicate metadata part of identity."""
    merged = dict(current)
    for key, value in candidate.items():
        key_text = _text(key)
        if not key_text or not _text(value):
            continue
        if key_text not in merged or not _text(merged[key_text]):
            merged[key_text] = value
            continue
        if _text(merged[key_text]) == _text(value):
            continue
        # Preserve both non-empty observations deterministically.  This is
        # uncommon, but it is safer than silently dropping parser evidence.
        values = merged[key_text]
        if not isinstance(values, list):
            values = [values]
        if value not in values:
            values.append(value)
        merged[key_text] = sorted(values, key=lambda item: _text(item))
    return merged


def build_recovery_worklist(
    diagnostics: Mapping[str, Any],
    functions: Any,
    *,
    entry_point_ids: Iterable[str] | None = None,
    max_sites: int = DEFAULT_MAX_SITES,
    max_shortlist: int = DEFAULT_MAX_SHORTLIST,
    max_code_bytes: int = DEFAULT_MAX_CODE_BYTES,
    include_candidate_sites: bool = False,
    security_relevant_only: bool = False,
    include_registration_context: bool = False,
    registration_context_max_files: int = DEFAULT_REGISTRATION_CONTEXT_MAX_FILES,
    registration_context_max_file_bytes: int = DEFAULT_REGISTRATION_CONTEXT_MAX_FILE_BYTES,
    registration_context_max_chars: int = DEFAULT_REGISTRATION_CONTEXT_MAX_CHARS,
    repository: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Build a bounded, prioritized list of residual sites for an LLM.

    By default only sites without deterministic candidates are included.  A
    caller can opt into candidate-bearing sites for a later verification pass,
    but that is intentionally not the first-stage behavior.  The optional
    ``security_relevant_only`` mode keeps only sites with a known entry-point
    or a conservative IPC/network/command boundary signal for cost control;
    sites already classified as external boundaries are retained as metadata
    but are not sent to the in-repository LLM review queue.
    """
    if not isinstance(diagnostics, Mapping):
        return []
    index = _normalize_functions(functions)
    entry_ids = {_text(item) for item in (entry_point_ids or []) if _text(item)}
    source_root = repository if repository is not None else diagnostics.get("repository")
    grouped: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    for source, raw_site in _raw_sites(diagnostics):
        candidate_ids = raw_site.get("candidate_target_ids", [])
        if not isinstance(candidate_ids, list):
            candidate_ids = []
        if candidate_ids and not include_candidate_sites:
            continue
        caller_id = _text(raw_site.get("caller_id"))
        caller = index.get(caller_id)
        if not caller:
            continue
        key = _raw_site_key(source, raw_site, caller)
        expression = key[3]
        line = key[2]
        file_path = key[1]
        reason = _text(raw_site.get("reason"))
        symbols = (
            dict(raw_site.get("symbols"))
            if isinstance(raw_site.get("symbols"), Mapping)
            else {}
        )
        priority, security_relevant, priority_reason = _site_priority(
            raw_site, caller, entry_ids
        )
        classification = classify_recovery_site(raw_site, caller)
        item = grouped.get(key)
        if item is None:
            item = {
                "source": source,
                "caller_ids": [],
                "callers": {},
                "caller": None,
                "caller_id": "",
                "file": file_path,
                "line": line,
                "expression": expression,
                "reason": reason,
                "symbols": symbols,
                "candidate_target_ids": [],
                "priority": priority,
                "security_relevant": security_relevant,
                "priority_reason": priority_reason,
                "classification": classification,
                "duplicate_count": 0,
                "_raw_site": dict(raw_site),
                "_priority_rank": _CONFIDENCE_RANK.get(priority, 0),
            }
            grouped[key] = item
        if caller_id not in item["caller_ids"]:
            item["caller_ids"].append(caller_id)
            item["callers"][caller_id] = caller
        item["duplicate_count"] += 1
        if not item["reason"] and reason:
            item["reason"] = reason
        item["symbols"] = _merge_symbols(item["symbols"], symbols)
        for target_id in candidate_ids:
            target_id = _text(target_id)
            if target_id and target_id not in item["candidate_target_ids"]:
                item["candidate_target_ids"].append(target_id)
        item["classification"] = _merge_classification(
            item["classification"], classification
        )
        priority_rank = _CONFIDENCE_RANK.get(priority, 0)
        if priority_rank > item["_priority_rank"]:
            item["priority"] = priority
            item["priority_reason"] = priority_reason
            item["_priority_rank"] = priority_rank
        item["security_relevant"] = item["security_relevant"] or security_relevant

    worklist: list[dict[str, Any]] = []
    for item in grouped.values():
        caller_ids = sorted(item["caller_ids"])
        if not caller_ids:
            continue
        caller_id = caller_ids[0]
        caller = item["callers"][caller_id]
        classification = item["classification"]
        if security_relevant_only and (
            not item["security_relevant"]
            or classification.get("analysis_route") == "external_boundary"
        ):
            continue
        raw_site = dict(item["_raw_site"])
        raw_site["caller_id"] = caller_id
        raw_site["file"] = item["file"]
        raw_site["line"] = item["line"]
        raw_site["expression"] = item["expression"]
        raw_site["reason"] = item["reason"]
        raw_site["symbols"] = item["symbols"]
        raw_site["candidate_target_ids"] = item["candidate_target_ids"]
        work_item = {
            "site_id": _site_id(
                item["source"],
                caller_id,
                item["line"],
                item["expression"],
                file_path=item["file"],
            ),
            "source": item["source"],
            "caller_id": caller_id,
            "caller_ids": caller_ids,
            "duplicate_count": item["duplicate_count"],
            "caller": _project_function(
                caller_id, caller, max_code_bytes=max_code_bytes
            ),
            "file": item["file"],
            "line": item["line"],
            "expression": item["expression"],
            "reason": item["reason"],
            "symbols": item["symbols"],
            "candidate_target_ids": sorted(item["candidate_target_ids"]),
            "candidate_count": len(item["candidate_target_ids"]),
            "priority": item["priority"],
            "security_relevant": item["security_relevant"],
            "priority_reason": item["priority_reason"],
            "classification": classification,
            "analysis_route": classification["analysis_route"],
            "llm_eligible": classification["llm_eligible"],
            "review_scope": (
                "candidate_edges"
                if item["candidate_target_ids"]
                else "unknown_indirect"
            ),
            "retrieval_candidates": _shortlist_functions(
                raw_site,
                caller,
                index,
                max_items=max_shortlist,
                max_code_bytes=max_code_bytes,
                required_function_ids=(
                    item["candidate_target_ids"]
                    if include_candidate_sites
                    else ()
                ),
            ),
        }
        if include_registration_context:
            work_item["registration_context"] = build_registration_context(
                work_item,
                index,
                repository=source_root,
                max_files=registration_context_max_files,
                max_file_bytes=registration_context_max_file_bytes,
                max_context_chars=registration_context_max_chars,
            )
        worklist.append(work_item)
    worklist.sort(
        key=lambda item: (
            -_CONFIDENCE_RANK.get(item["priority"], 0),
            not item["security_relevant"],
            item["file"],
            item["line"],
            item["site_id"],
        )
    )
    if max_sites < 0:
        return worklist
    return worklist[:max_sites]


def build_recovery_prompt(
    worklist: Sequence[Mapping[str, Any]],
    *,
    max_prompt_chars: int = 120_000,
) -> str:
    """Render the strict edge-recovery prompt without invoking an LLM."""
    payload = {
        "schema_version": RECOVERY_SCHEMA_VERSION,
        "task": RECOVERY_TASK,
        "rules": [
            "Only propose a target_id that appears in retrieval_candidates.",
            "A proposal needs both call_site and target/registration evidence.",
            "Use registration_context source excerpts to verify table writes, initialization, and parameter flow; do not treat a file path or a name alone as registration evidence.",
            "registration_context.snippets may include line_numbered_text; use those numbers for evidence spans, but keep evidence.text as source code without the '<line> |' prefix.",
            "Each evidence.text must be a single-line JSON string. Do not put literal line breaks inside it; quote one key source line, or encode a source newline as the JSON escape sequence \\n.",
            "Do not infer an edge from a name alone or from a generic callback type.",
            "For external_boundary sites, do not invent an in-repository target; keep_unresolved.",
            "If the source is ambiguous, return keep_unresolved.",
        ],
        "sites": [dict(item) for item in worklist],
    }
    serialized = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if len(serialized) > max_prompt_chars:
        serialized = serialized[: max(0, max_prompt_chars - 40)] + "\n...[truncated]"
    fence = safe_code_fence(serialized)
    return f"""你是 OpenHarmony C/C++ 调用图复核器。你只能在给定的残余调用点和检索候选中判断，不能创造函数 ID。

    对每个 site 输出一个或多个 decision（候选列表中每条确认边输出一条 add_edge）：
- add_edge：只有调用点、目标函数和注册/类型证据都明确时使用；
- keep_unresolved：证据不足、来源有歧义或目标不在候选列表时使用。

对 candidate-bearing site，add_edge 的 target_id 必须同时出现在
candidate_target_ids 和 retrieval_candidates；不要因为名称相似而补充其他函数。
如果 registration_context.status 不是 found，或片段没有显示注册/初始化关系，保持
keep_unresolved；文件路径和函数名本身不算注册证据。`evidence.text` 必须是单行字符串，
不得把真实换行直接放入 JSON 字符串；需要多行时只引用其中一条关键源码行。

严格返回 JSON，不要 Markdown，不要额外说明：
{{"schema_version": 1, "decisions": [{{"site_id": "...", "decision": "add_edge|keep_unresolved", "target_id": "", "confidence": "high|medium|low", "reason": "", "evidence": [{{"kind": "call_site|registration|target|type", "file": "", "start_line": 1, "end_line": 1, "text": ""}}]}}]}}

输入上下文：
{fence}json
{serialized}
{fence}
"""


def _retry_prompt(prompt: str, parse_errors: Sequence[str]) -> str:
    """Add a bounded, format-specific correction without duplicating context."""
    details = "; ".join(_text(error)[:240] for error in parse_errors[:4])
    if not details:
        details = "the previous response did not satisfy the response contract"
    return (
        f"{prompt}\n\n"
        "上一轮响应未通过严格 JSON 校验。请在保持相同输入和 site_id 的前提下重新输出，"
        "只允许一个 JSON 对象，不要 Markdown、解释或思考过程；每个 evidence.text 必须是"
        "不含真实换行的单行 JSON 字符串（源码换行请写成 \\n 转义，或只引用一行）。"
        f"上一轮校验提示：{details}"
    )


def _response_metadata(response: str) -> dict[str, Any]:
    """Return non-sensitive diagnostics for a response that failed parsing."""
    first_brace = response.find("{")
    last_brace = response.rfind("}")
    return {
        "response_chars": len(response),
        "response_sha256": hashlib.sha256(response.encode("utf-8", errors="replace")).hexdigest(),
        "first_brace_offset": first_brace,
        "last_brace_offset": last_brace,
        "candidate_chars": (
            last_brace - first_brace + 1
            if first_brace >= 0 and last_brace > first_brace
            else 0
        ),
        "contains_markdown_fence": "```" in response,
    }


def _extract_json(text: str) -> dict[str, Any] | None:
    cleaned = _text(text)
    if not cleaned:
        return None
    fence = re.match(
        r"^```(?:json)?\s*(?P<body>.*?)\s*```$",
        cleaned,
        re.DOTALL | re.IGNORECASE,
    )
    if fence:
        cleaned = fence.group("body").strip()
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        parsed = json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _error(log: Callable[[str], None], message: str) -> None:
    log(message)


def _parse_evidence(
    raw: Any,
    *,
    log: Callable[[str], None],
    index: int,
) -> list[dict[str, Any]] | None:
    if not isinstance(raw, list) or not raw:
        _error(log, f"decision #{index}: evidence must be a non-empty list")
        return None
    evidence: list[dict[str, Any]] = []
    for evidence_index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            _error(log, f"decision #{index} evidence #{evidence_index}: not an object")
            return None
        kind = _text(item.get("kind"))
        file_path = _text(item.get("file"))
        text = _text(item.get("text"))
        start_line = _line(item.get("start_line", 1))
        end_line = _line(item.get("end_line", start_line))
        if kind not in _VALID_EVIDENCE_KINDS or not file_path or not text:
            _error(log, f"decision #{index} evidence #{evidence_index}: incomplete evidence")
            return None
        if "\n" in text or "\r" in text:
            _error(
                log,
                f"decision #{index} evidence #{evidence_index}: evidence.text must be single-line",
            )
            return None
        if end_line < start_line:
            _error(log, f"decision #{index} evidence #{evidence_index}: invalid line range")
            return None
        evidence.append(
            {
                "kind": kind,
                "function_id": _text(item.get("function_id")),
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "text": text[:2_000],
            }
        )
    return evidence


def parse_recovery_response(
    response_text: str,
    *,
    valid_site_ids: set[str],
    valid_function_ids: set[str],
    on_error: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Parse and shape model decisions; malformed decisions are discarded."""
    log = on_error or (lambda _message: None)
    data = _extract_json(response_text)
    if not isinstance(data, Mapping):
        _error(log, "response is not a JSON object")
        return []
    if data.get("schema_version") != RECOVERY_SCHEMA_VERSION:
        _error(log, "response.schema_version is unsupported")
        return []
    decisions = data.get("decisions")
    if not isinstance(decisions, list):
        _error(log, "response.decisions is not a list")
        return []
    parsed: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(decisions):
        if not isinstance(raw, Mapping):
            _error(log, f"decision #{index}: not an object")
            continue
        site_id = _text(raw.get("site_id"))
        decision = _text(raw.get("decision"))
        confidence = _text(raw.get("confidence"))
        target_id = _text(raw.get("target_id"))
        reason = _text(raw.get("reason"))[:500]
        if site_id not in valid_site_ids:
            _error(log, f"decision #{index}: unknown site_id")
            continue
        if decision not in _VALID_DECISIONS:
            _error(log, f"decision #{index}: invalid decision")
            continue
        if confidence not in _VALID_CONFIDENCES:
            _error(log, f"decision #{index}: invalid confidence")
            continue
        if decision == "add_edge":
            if target_id not in valid_function_ids:
                _error(log, f"decision #{index}: unknown target_id")
                continue
            if not reason:
                _error(log, f"decision #{index}: add_edge needs a reason")
                continue
        elif target_id and target_id not in valid_function_ids:
            _error(log, f"decision #{index}: keep_unresolved has unknown target_id")
            continue
        evidence = _parse_evidence(raw.get("evidence"), log=log, index=index)
        if evidence is None:
            continue
        key = (site_id, target_id if decision == "add_edge" else "")
        if key in seen:
            _error(log, f"decision #{index}: duplicate site/target")
            continue
        seen.add(key)
        parsed.append(
            {
                "site_id": site_id,
                "decision": decision,
                "target_id": target_id,
                "confidence": confidence,
                "reason": reason,
                "evidence": evidence,
            }
        )
    return parsed


def validate_recovery_proposals(
    proposals: Sequence[Mapping[str, Any]],
    worklist: Sequence[Mapping[str, Any]],
    functions: Any,
    *,
    minimum_confidence: str = "high",
) -> dict[str, list[dict[str, Any]]]:
    """Validate source-backed proposals without projecting graph edges."""
    index = _normalize_functions(functions)
    sites = { _text(item.get("site_id")): item for item in worklist }
    threshold = _CONFIDENCE_RANK.get(minimum_confidence, _CONFIDENCE_RANK["high"])
    accepted: list[dict[str, Any]] = []
    kept_unresolved: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for proposal in proposals:
        item = dict(proposal)
        site_id = _text(item.get("site_id"))
        decision = _text(item.get("decision"))
        if site_id not in sites:
            item["rejection_reason"] = "unknown_site"
            rejected.append(item)
            continue
        if decision == "keep_unresolved":
            kept_unresolved.append(item)
            continue
        target_id = _text(item.get("target_id"))
        target = index.get(target_id)
        if target is None:
            item["rejection_reason"] = "unknown_target"
            rejected.append(item)
            continue
        site = sites[site_id]
        candidate_ids = {
            _text(candidate_id)
            for candidate_id in site.get("candidate_target_ids", [])
            if _text(candidate_id)
        }
        if candidate_ids and target_id not in candidate_ids:
            item["rejection_reason"] = "target_not_in_candidate_targets"
            rejected.append(item)
            continue
        retrieval_ids = {
            _text(candidate.get("function_id"))
            for candidate in site.get("retrieval_candidates", [])
            if isinstance(candidate, Mapping) and _text(candidate.get("function_id"))
        }
        if target_id not in retrieval_ids:
            item["rejection_reason"] = "target_not_in_retrieval_candidates"
            rejected.append(item)
            continue
        confidence = _text(item.get("confidence"))
        if _CONFIDENCE_RANK.get(confidence, -1) < threshold:
            item["rejection_reason"] = "confidence_below_threshold"
            rejected.append(item)
            continue
        evidence = item.get("evidence")
        if not isinstance(evidence, list):
            item["rejection_reason"] = "missing_evidence"
            rejected.append(item)
            continue
        target_file = _text(target.get("file_path") or target.get("filePath"))
        has_call_site = any(
            isinstance(entry, Mapping) and entry.get("kind") == "call_site"
            for entry in evidence
        )
        has_target_evidence = any(
            isinstance(entry, Mapping)
            and entry.get("kind") in {"target", "registration", "type"}
            and (
                not target_file
                or _text(entry.get("file")) == target_file
                or _text(entry.get("function_id")) == target_id
            )
            for entry in evidence
        )
        if not has_call_site or not has_target_evidence:
            item["rejection_reason"] = "insufficient_source_evidence"
            rejected.append(item)
            continue
        item["validation"] = "accepted_for_review"
        accepted.append(item)
    return {
        "accepted": accepted,
        "kept_unresolved": kept_unresolved,
        "rejected": rejected,
    }


def run_recovery_review(
    diagnostics: Mapping[str, Any],
    functions: Any,
    *,
    binding: Any = None,
    completion: Callable[[str], str] | None = None,
    entry_point_ids: Iterable[str] | None = None,
    max_sites: int = DEFAULT_MAX_SITES,
    max_shortlist: int = DEFAULT_MAX_SHORTLIST,
    max_code_bytes: int = DEFAULT_MAX_CODE_BYTES,
    include_candidate_sites: bool = False,
    security_relevant_only: bool = False,
    include_registration_context: bool = True,
    registration_context_max_files: int = DEFAULT_REGISTRATION_CONTEXT_MAX_FILES,
    registration_context_max_file_bytes: int = DEFAULT_REGISTRATION_CONTEXT_MAX_FILE_BYTES,
    registration_context_max_chars: int = DEFAULT_REGISTRATION_CONTEXT_MAX_CHARS,
    repository: str | Path | None = None,
    max_retries: int = 2,
    retry_backoff_seconds: float = 1.0,
    max_tokens: int = 20_000,
    tracker: Any = None,
    site_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Execute one bounded LLM review without changing any graph artifact.

    ``completion`` is an injectable ``prompt -> text`` function used by
    offline tests and integrations that own their adapter call.  Production
    callers can omit it and provide a phase ``binding``; the shared
    :func:`utilities.llm.simple_text` helper then performs the request and
    records token usage on the supplied tracker.

    Retries cover transport failures and malformed/invalid JSON responses.  A
    valid response that deliberately keeps a site unresolved is not retried.
    ``site_ids`` optionally limits the review to a previously built subset;
    this is used by the entry-driven round scheduler so one call does not
    resubmit residual sites that belong to a later BFS frontier.  The returned
    object contains only JSON-serialisable worklist, decisions, validation,
    and telemetry; callers may persist it as an advisory artifact but must not
    treat it as a replacement for ``call_graph.json``.
    """
    worklist = build_recovery_worklist(
        diagnostics,
        functions,
        entry_point_ids=entry_point_ids,
        max_sites=max_sites,
        max_shortlist=max_shortlist,
        max_code_bytes=max_code_bytes,
        include_candidate_sites=include_candidate_sites,
        security_relevant_only=security_relevant_only,
        include_registration_context=include_registration_context,
        registration_context_max_files=registration_context_max_files,
        registration_context_max_file_bytes=registration_context_max_file_bytes,
        registration_context_max_chars=registration_context_max_chars,
        repository=repository,
    )
    if site_ids is not None:
        selected_site_ids = {
            _text(site_id) for site_id in site_ids if _text(site_id)
        }
        worklist = [
            item for item in worklist
            if _text(item.get("site_id")) in selected_site_ids
        ]
    prompt = build_recovery_prompt(worklist)
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    base_summary = {
        "worklist_sites": len(worklist),
        "attempts": 0,
        "llm_calls": 0,
        "retry_count": 0,
        "parsed_decisions": 0,
        "accepted": 0,
        "kept_unresolved": 0,
        "rejected": 0,
        "unreviewed_sites": len(worklist),
    }
    if not worklist:
        return {
            "schema_version": RECOVERY_SCHEMA_VERSION,
            "task": RECOVERY_TASK,
            "status": "no_sites",
            "prompt_sha256": prompt_hash,
            "worklist": [],
            "decisions": [],
            "validation": {"accepted": [], "kept_unresolved": [], "rejected": []},
            "errors": [],
            "response_diagnostics": [],
            "summary": base_summary,
        }

    try:
        retries = max(0, int(max_retries))
    except (TypeError, ValueError):
        retries = 2
    try:
        backoff = max(0.0, float(retry_backoff_seconds))
    except (TypeError, ValueError):
        backoff = 1.0

    errors: list[dict[str, Any]] = []
    parsed: list[dict[str, Any]] = []
    validation: dict[str, list[dict[str, Any]]] = {
        "accepted": [],
        "kept_unresolved": [],
        "rejected": [],
    }
    attempts = 0
    successful_parse = False
    attempt_prompt = prompt
    response_diagnostics: list[dict[str, Any]] = []

    for attempt in range(1, retries + 2):
        attempts = attempt
        try:
            if completion is not None:
                response = completion(attempt_prompt)
            else:
                if binding is None:
                    raise ValueError(
                        "run_recovery_review requires completion or binding"
                    )
                from utilities.llm import simple_text

                response = simple_text(
                    binding,
                    attempt_prompt,
                    max_tokens=max_tokens,
                    tracker=tracker,
                )
            if not isinstance(response, str):
                raise TypeError("model completion must return text")
        except Exception as exc:  # noqa: BLE001 - retry boundary is intentional
            response_diagnostics.append(
                {
                    "attempt": attempt,
                    "status": "transport_error",
                    "error_type": type(exc).__name__,
                }
            )
            errors.append(
                {
                    "attempt": attempt,
                    "type": type(exc).__name__,
                    "message": str(exc)[:500],
                }
            )
        else:
            parse_errors: list[str] = []
            parsed_candidate = parse_recovery_response(
                response,
                valid_site_ids={item["site_id"] for item in worklist},
                valid_function_ids=set(_normalize_functions(functions)),
                on_error=parse_errors.append,
            )
            response_meta = _response_metadata(response)
            if parse_errors:
                response_diagnostics.append(
                    {
                        "attempt": attempt,
                        "status": "invalid",
                        "response": response_meta,
                        "parse_errors": parse_errors[:8],
                    }
                )
                errors.extend(
                    {
                        "attempt": attempt,
                        "type": "response_validation",
                        "message": message[:500],
                        "response": response_meta,
                    }
                    for message in parse_errors
                )
                parsed = parsed_candidate
                if attempt <= retries:
                    attempt_prompt = _retry_prompt(prompt, parse_errors)
            else:
                response_diagnostics.append(
                    {
                        "attempt": attempt,
                        "status": "valid",
                        "response": response_meta,
                    }
                )
                source_root = (
                    repository
                    if repository is not None
                    else diagnostics.get("repository")
                )
                parsed = normalize_recovery_evidence(
                    parsed_candidate,
                    worklist,
                    functions,
                    repository=source_root,
                )
                validation = validate_recovery_proposals(
                    parsed,
                    worklist,
                    functions,
                )
                successful_parse = True
                break

        if attempt <= retries and backoff:
            time.sleep(backoff * attempt)

    if not successful_parse:
        # Keep any syntactically valid subset visible to the reviewer, but do
        # not label it accepted because the overall response never passed the
        # strict parser contract.
        if parsed:
            source_root = (
                repository
                if repository is not None
                else diagnostics.get("repository")
            )
            parsed = normalize_recovery_evidence(
                parsed,
                worklist,
                functions,
                repository=source_root,
            )
            validation = validate_recovery_proposals(parsed, worklist, functions)
        status = "failed"
    else:
        status = "complete"

    summary = {
        **base_summary,
        "attempts": attempts,
        "llm_calls": attempts,
        "retry_count": max(0, attempts - 1),
        "parsed_decisions": len(parsed),
        "accepted": len(validation["accepted"]),
        "kept_unresolved": len(validation["kept_unresolved"]),
        "rejected": len(validation["rejected"]),
        "unreviewed_sites": max(
            0,
            len(worklist)
            - len({item.get("site_id") for item in parsed}),
        ),
        "evidence_line_resolution": summarize_line_resolution(parsed),
    }
    return {
        "schema_version": RECOVERY_SCHEMA_VERSION,
        "task": RECOVERY_TASK,
        "status": status,
        "prompt_sha256": prompt_hash,
        "worklist": worklist,
        "decisions": parsed,
        "validation": validation,
        "errors": errors,
        "response_diagnostics": response_diagnostics,
        "summary": summary,
    }


__all__ = [
    "DEFAULT_MAX_CODE_BYTES",
    "DEFAULT_MAX_SHORTLIST",
    "RECOVERY_SCHEMA_VERSION",
    "RECOVERY_TASK",
    "build_recovery_prompt",
    "build_recovery_worklist",
    "classify_recovery_site",
    "parse_recovery_response",
    "run_recovery_review",
    "validate_recovery_proposals",
]
