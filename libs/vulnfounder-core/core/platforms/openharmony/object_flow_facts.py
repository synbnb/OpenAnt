"""统一整理 OpenHarmony C/C++ 对象和值流的第一批候选事实。

本模块的目标不是在没有完整类型系统的情况下“猜出”运行时对象，而是把
已有调用点台账、分派诊断和源码中的工厂调用整理成一个可复查的事实层：

* ``dispatch_registration``：表项、函数指针或成员函数绑定；
* ``callback_registration``：lambda / 回调注册及其捕获的调用目标；
* ``parameter_flow``：局部表或可调用对象传入下游参数的证据；
* ``indirect_call_site``：通过表、函数指针或 ``std::function`` 触发的站点；
* ``factory_value_flow``：工厂、``GetInstance`` 或智能指针构造返回值的观察；
* ``call_site_candidate``：普通调用点存在候选目标但尚未满足严格绑定条件。

所有关系都保持 ``candidate`` 层级，不能单独生成 strict 调用边。每条事实
保留源码位置、表达式和来源记录，供后续对象流求解器、LLM 复核或 Stage 2
补证使用。这样即使候选集合不完整，也不会把“尚未证明”误写成“没有关系”。
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Mapping
from typing import Any


SCHEMA_VERSION = 1
IMPLEMENTATION_VERSION = "v2_cross_function_and_symbol_frontier"
REPORT_TYPE = "openharmony_object_flow_facts"
OVERLAY_TYPE = "openharmony_object_flow_candidate_overlay"


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple, set)) else []


def _normal_endpoint(value: Any) -> str:
    result = _text(value)
    return result[len("function:") :] if result.startswith("function:") else result


def _fact_id(
    kind: str,
    caller: str,
    target: str,
    file_path: str,
    line: Any,
    expression: str,
    source: str,
) -> str:
    raw = "|".join(
        [kind, caller, target, file_path, _text(line), expression, source]
    )
    return "object-flow:" + hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:24]


def _evidence(
    record: Mapping[str, Any],
    *,
    file_path: str = "",
    line: Any = None,
    expression: str = "",
) -> dict[str, Any]:
    raw = record.get("evidence")
    result = dict(raw) if isinstance(raw, Mapping) else {}
    result.setdefault("file", file_path or record.get("file", ""))
    result.setdefault("start_line", line if line is not None else record.get("line"))
    result.setdefault("end_line", result.get("start_line"))
    result.setdefault("text", expression or record.get("expression", ""))
    return result


def _fact(
    facts: list[dict[str, Any]],
    seen: set[str],
    *,
    kind: str,
    caller: str = "",
    target: str = "",
    file_path: str = "",
    line: Any = None,
    expression: str = "",
    source: str,
    evidence: Mapping[str, Any] | None = None,
    attributes: Mapping[str, Any] | None = None,
    value: Mapping[str, Any] | None = None,
) -> str:
    caller = _normal_endpoint(caller)
    target = _normal_endpoint(target)
    fact_id = _fact_id(kind, caller, target, file_path, line, expression, source)
    if fact_id in seen:
        return fact_id
    seen.add(fact_id)
    facts.append(
        {
            "fact_id": fact_id,
            "fact_kind": kind,
            "status": "candidate",
            "confidence": "candidate",
            "caller_id": caller or None,
            "target_id": target or None,
            "file": file_path,
            "line_start": line,
            "line_end": line,
            "expression": expression,
            "source": source,
            "evidence": dict(evidence or {}),
            "value": dict(value or {}),
            "attributes": {
                "evidence_level": "syntax_observation",
                "strict_admission": False,
                **dict(attributes or {}),
            },
        }
    )
    return fact_id


_FACTORY_RE = re.compile(
    r"(?:make_(?:shared|unique|allocated)|allocate_shared|GetInstance|GetProfilerItem|Factory)",
    re.IGNORECASE,
)


def _is_factory_expression(expression: str) -> bool:
    return bool(_FACTORY_RE.search(expression or ""))


def _function_name(function: Mapping[str, Any]) -> str:
    return _text(function.get("name"))


def _owner_qualified_hint(record: Mapping[str, Any]) -> str:
    """Recover a conservative receiver owner from a source call shape."""
    receiver = _text(record.get("receiver_expression"))
    callee = _text(record.get("callee_spelling"))
    expression = _text(record.get("expression"))
    # Static calls carry the owner in ``Class::Method`` directly.
    if "::" in callee:
        return callee.rsplit("::", 1)[0].strip()
    # A chained member call commonly has ``Class::GetInstance()`` as the
    # receiver.  Remove the invocation and retain the qualified class.
    match = re.search(
        r"(?P<owner>[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*::\s*GetInstance\s*\(",
        receiver or expression,
    )
    if match:
        return match.group("owner")
    return ""


def _refine_candidate_targets(
    record: Mapping[str, Any],
    functions: Mapping[str, Any],
) -> tuple[list[str], list[str]]:
    """Narrow broad leaf-name candidates using an explicit receiver owner.

    The legacy ledger intentionally keeps a broad shortlist for ambiguous
    member calls.  For a qualified factory/member expression we can safely
    use the class spelling as an additional constraint.  If the owner is
    external or absent from the index, return no target rather than mapping
    one call to every same-named ``GetInstance`` method.  Unknown local
    receivers keep their original shortlist for later semantic recovery.
    """
    raw = [_normal_endpoint(value) for value in _list(record.get("candidate_target_ids")) if _normal_endpoint(value)]
    raw = list(dict.fromkeys(raw))
    owner = _owner_qualified_hint(record)
    if not owner:
        # An unqualified ``GetInstance()`` inside a class method is often a
        # same-class singleton call.  Recover that only when the caller's
        # qualified identity gives us the class unambiguously.
        caller = _text(record.get("caller_id"))
        caller_name = caller.rsplit(":", 1)[-1]
        if "::" in caller_name:
            owner = caller_name.rsplit("::", 1)[0]
    if not owner:
        return raw, raw
    owner_leaf = owner.rsplit("::", 1)[-1]
    method = _text(record.get("callee_spelling"))
    method = method.rsplit("::", 1)[-1] if method else ""
    matched: list[str] = []
    for target_id in raw:
        function = functions.get(target_id)
        name = _function_name(function) if isinstance(function, Mapping) else target_id
        if not method:
            continue
        # Match the complete owner when available, while accepting a
        # namespace-qualified index whose suffix ends in Owner::Method.
        if name == f"{owner}::{method}" or name.endswith(f"::{owner}::{method}"):
            matched.append(target_id)
            continue
        if name.endswith(f"::{owner_leaf}::{method}"):
            matched.append(target_id)
    if matched:
        return raw, sorted(set(matched))
    # A broad leaf-only shortlist is useful to an LLM recovery task, but it
    # is not a useful object-flow edge.  Keep the fact and raw candidates
    # while suppressing the misleading overlay when the owner cannot be
    # proven.  Small lists (for example two overloads) remain candidates for
    # later semantic review.
    if len(raw) > 8:
        return raw, []
    return raw, raw


_ASSIGNMENT_RE = re.compile(
    r"(?P<lhs>(?:this\s*(?:->|\.)\s*)?[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)"
    r"\s*=\s*(?P<rhs>[^;]+);"
)
_RETURN_RE = re.compile(r"\breturn\s+(?P<value>[^;]+);")
_CALL_RE = re.compile(r"(?P<callee>[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\((?P<args>[^;]*)\)")
_FUNCTION_POINTER_TYPE_RE = re.compile(
    r"(?:typedef\s+[^;]*\(\s*\*\s*(?P<typedef>[A-Za-z_]\w*)\s*\)|"
    r"using\s+(?P<using>[A-Za-z_]\w*)\s*=\s*[^;]*\(\s*\*)"
)
_FUNCTION_POINTER_ASSIGN_RE = re.compile(
    r"(?:(?P<type>[A-Za-z_]\w*)\s+)?(?P<variable>[A-Za-z_]\w*)\s*=\s*"
    r"\((?P<cast>[^)]*\*?[^)]*)\)\s*(?P<origin>dlsym|reinterpret_cast|"
    r"[A-Za-z_]\w*::GetInstance|[^;]+);"
)
_QUALIFIED_POINTER_ASSIGN_RE = re.compile(
    r"(?P<type>[A-Za-z_]\w*)\s+(?P<variable>[A-Za-z_]\w*)\s*=\s*"
    r"&(?P<origin>[A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)\s*;"
)
_LAMBDA_RE = re.compile(r"\[(?P<capture>[^\]]*)\]\s*(?:\([^)]*\))?\s*\{")
_LAMBDA_BODY_RE = re.compile(
    r"\[(?P<capture>[^\]]*)\]\s*(?:\([^)]*\))?\s*\{(?P<body>.*?)\}",
    re.DOTALL,
)
_THIS_CALL_RE = re.compile(r"\bthis\s*(?:->|\.)\s*(?P<method>[A-Za-z_]\w*)\s*\(")
_VALUE_ORIGIN_RE = re.compile(
    r"(?:GetInstance\s*\(|make_(?:shared|unique|allocated)\s*<|allocate_shared\s*<|\bnew\s+[A-Za-z_])"
)
_CALLBACK_API_RE = re.compile(
    r"(?P<api>(?:std::thread|[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*"
    r"|[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*))\s*\([^()]*$"
)


def _parameter_names(function: Mapping[str, Any]) -> list[str]:
    """Extract only simple parameter names for conservative summaries."""
    result: list[str] = []
    for parameter in _list(function.get("parameters")):
        text = _text(parameter)
        if not text:
            continue
        # Keep the last identifier, excluding a trailing array/function suffix.
        matches = re.findall(r"[A-Za-z_]\w*", text)
        if not matches:
            continue
        name = matches[-1]
        if name in {"const", "volatile", "noexcept"}:
            continue
        result.append(name)
    return result


def _split_arguments(arguments: str) -> list[str]:
    """Split a call argument list without pretending to parse C++ fully."""
    values: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(arguments):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"\"", "'"}:
            quote = char
            continue
        if char in "([{<":
            depth += 1
        elif char in ")]}>" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            values.append(arguments[start:index].strip())
            start = index + 1
    tail = arguments[start:].strip()
    if tail:
        values.append(tail)
    return values


def _direct_function_targets(origin: str, functions: Mapping[str, Any]) -> list[str]:
    """Resolve an explicitly qualified function/member reference conservatively."""
    text = re.sub(r"[&*()\s]", "", origin or "")
    if "::" not in text:
        return []
    matches: list[str] = []
    for function_id, function in functions.items():
        if not isinstance(function_id, str) or not isinstance(function, Mapping):
            continue
        name = _text(function.get("name"))
        if name == text or name.endswith(f"::{text}"):
            matches.append(function_id)
    return sorted(set(matches))


def _line_for_function(function: Mapping[str, Any], line: Any) -> str:
    code = function.get("code")
    if not isinstance(code, str):
        return ""
    try:
        offset = int(line) - int(function.get("start_line", function.get("startLine", 1)))
    except (TypeError, ValueError):
        return ""
    lines = code.splitlines()
    return lines[offset].strip() if 0 <= offset < len(lines) else ""


def _source_value_flow_facts(
    extract_result: Mapping[str, Any],
    facts: list[dict[str, Any]],
    seen: set[str],
) -> None:
    """Add small, syntax-backed local value-flow observations.

    This pass intentionally handles only same-function assignments, member
    writes, returns and obvious factory/new expressions.  It does not infer a
    type or a dynamic target; the resulting records are useful for scheduling
    deeper resolution but never become strict edges by themselves.
    """
    functions = extract_result.get("functions", {})
    if not isinstance(functions, Mapping):
        return
    for function_id, function in functions.items():
        if not isinstance(function_id, str) or not isinstance(function, Mapping):
            continue
        code = function.get("code")
        if not isinstance(code, str) or not code:
            continue
        file_path = _text(function.get("file_path"))
        start_line = function.get("start_line", function.get("startLine", 1))
        try:
            start_line = int(start_line)
        except (TypeError, ValueError):
            start_line = 1
        known_values: dict[str, str] = {}
        pointer_types: dict[str, str] = {}
        pointer_variables: dict[str, str] = {}
        pointer_targets: dict[str, list[str]] = {}
        lines = code.splitlines()
        owner_class = _text(function.get("class_name"))
        if not owner_class:
            function_name = _text(function.get("name"))
            if "::" in function_name:
                owner_class = function_name.rsplit("::", 1)[0].rsplit("::", 1)[-1]
        # A one-line or compact lambda often contains the actual callback
        # invocation in the same source span (for example a thread lambda).
        # Resolve only ``this->Method``/``this.Method`` against the containing
        # class; captured free objects remain unresolved facts.
        for lambda_match in _LAMBDA_BODY_RE.finditer(code):
            body = lambda_match.group("body")
            line = start_line + code.count("\n", 0, lambda_match.start())
            capture = lambda_match.group("capture")
            lambda_prefix = code[max(0, lambda_match.start() - 160) : lambda_match.start()]
            registration_match = _CALLBACK_API_RE.search(lambda_prefix)
            registration_api = registration_match.group("api") if registration_match else ""
            async_boundary = bool(
                re.search(r"std::thread|PostTask|PushTask|Async|Submit|Dispatch", lambda_prefix)
            )
            lambda_targets: list[str] = []
            for call_match in _THIS_CALL_RE.finditer(body):
                method = call_match.group("method")
                targets = []
                for target_id, target in functions.items():
                    if not isinstance(target_id, str) or not isinstance(target, Mapping):
                        continue
                    target_name = _text(target.get("name"))
                    target_owner = _text(target.get("class_name")).rsplit("::", 1)[-1]
                    if not target_owner and "::" in target_name:
                        target_owner = target_name.rsplit("::", 1)[0].rsplit("::", 1)[-1]
                    if target_name.endswith(f"::{method}") and (
                        not owner_class or not target_owner or target_owner == owner_class.rsplit("::", 1)[-1]
                    ):
                        targets.append(target_id)
                expression = call_match.group(0).strip()
                target_id = sorted(set(targets))[0] if len(set(targets)) == 1 else ""
                lambda_targets.extend(sorted(set(targets)))
                _fact(
                    facts,
                    seen,
                    kind="lambda_invocation",
                    caller=function_id,
                    target=target_id,
                    file_path=file_path,
                    line=line,
                    expression=expression,
                    source="object_flow_source_scan",
                    evidence={
                        "file": file_path,
                        "start_line": line,
                        "end_line": line,
                        "text": expression,
                    },
                    attributes={
                        "capture": capture,
                        "async_boundary": async_boundary,
                        "target_candidates": sorted(set(targets)),
                    },
                    value={"method": method, "capture": capture},
                )
            # A registration site is distinct from execution of the callback.
            # Keep both facts so later framework models can match the API,
            # event key and invocation condition without treating registration
            # itself as a synchronous call.
            if registration_api:
                callback_targets = sorted(set(lambda_targets))
                callback_target = callback_targets[0] if len(callback_targets) == 1 else ""
                _fact(
                    facts,
                    seen,
                    kind="callback_registration",
                    caller=function_id,
                    target=callback_target,
                    file_path=file_path,
                    line=line,
                    expression=registration_api,
                    source="object_flow_source_scan",
                    evidence={
                        "file": file_path,
                        "start_line": line,
                        "end_line": line,
                        "text": code[max(0, lambda_match.start() - 160) : lambda_match.end()].strip(),
                    },
                    attributes={
                        "registration_api": registration_api,
                        "capture": capture,
                        "async_boundary": async_boundary,
                        "target_candidates": callback_targets,
                        "execution_relation": "callback_invocation_required",
                    },
                    value={"capture": capture, "registration_api": registration_api},
                )
        # Parameters are value sources for the cross-function summary pass.
        # They are not treated as object types and do not create graph edges.
        for parameter in _parameter_names(function):
            known_values.setdefault(parameter, f"parameter:{parameter}")
        for offset, raw_line in enumerate(lines):
            line = start_line + offset
            text = raw_line.strip()
            if not text or text.startswith("//"):
                continue
            for pointer_match in _FUNCTION_POINTER_TYPE_RE.finditer(text):
                pointer_type = _text(pointer_match.group("typedef") or pointer_match.group("using"))
                if pointer_type:
                    pointer_types[pointer_type] = pointer_type
                    _fact(
                        facts,
                        seen,
                        kind="function_pointer_type",
                        caller=function_id,
                        file_path=file_path,
                        line=line,
                        expression=pointer_match.group(0).strip(),
                        source="object_flow_source_scan",
                        evidence={"file": file_path, "start_line": line, "end_line": line, "text": text},
                        attributes={"pointer_type": pointer_type},
                        value={"pointer_type": pointer_type},
                    )
            pointer_matches = list(_FUNCTION_POINTER_ASSIGN_RE.finditer(text))
            pointer_matches.extend(_QUALIFIED_POINTER_ASSIGN_RE.finditer(text))
            for pointer_match in pointer_matches:
                variable = _text(pointer_match.group("variable"))
                pointer_type = _text(pointer_match.group("type"))
                if not variable:
                    continue
                origin_text = _text(pointer_match.group("origin"))
                if (
                    pointer_type not in pointer_types
                    and not origin_text.startswith(("dlsym", "reinterpret_cast"))
                ):
                    continue
                pointer_variables[variable] = pointer_type or _text(
                    pointer_match.groupdict().get("cast", "")
                )
                targets = _direct_function_targets(origin_text, functions)
                pointer_targets[variable] = targets
                _fact(
                    facts,
                    seen,
                    kind="function_pointer_assignment",
                    caller=function_id,
                    target=targets[0] if len(targets) == 1 else "",
                    file_path=file_path,
                    line=line,
                    expression=text,
                    source="object_flow_source_scan",
                    evidence={"file": file_path, "start_line": line, "end_line": line, "text": text},
                    attributes={
                        "variable": variable,
                        "pointer_type": pointer_variables[variable],
                        "target_candidates": targets,
                        "resolution": "qualified_reference" if targets else "unknown",
                    },
                    value={"variable": variable, "origin": pointer_match.group("origin"), "target_candidates": targets},
                )
            for variable, pointer_type in pointer_variables.items():
                call_match = re.search(rf"\b{re.escape(variable)}\s*\(", text)
                if not call_match:
                    continue
                targets = pointer_targets.get(variable, [])
                _fact(
                    facts,
                    seen,
                    kind="function_pointer_call",
                    caller=function_id,
                    target=targets[0] if len(targets) == 1 else "",
                    file_path=file_path,
                    line=line,
                    expression=text,
                    source="object_flow_source_scan",
                    evidence={"file": file_path, "start_line": line, "end_line": line, "text": text},
                    attributes={
                        "variable": variable,
                        "pointer_type": pointer_type,
                        "dynamic_target": True,
                        "target_candidates": targets,
                        "resolution": "single_assignment_target" if len(targets) == 1 else "unknown",
                    },
                    value={"variable": variable, "target_candidates": targets},
                )
            for lambda_match in _LAMBDA_RE.finditer(text):
                _fact(
                    facts,
                    seen,
                    kind="lambda_expression",
                    caller=function_id,
                    file_path=file_path,
                    line=line,
                    expression=text,
                    source="object_flow_source_scan",
                    evidence={"file": file_path, "start_line": line, "end_line": line, "text": text},
                    attributes={"capture": lambda_match.group("capture"), "registration_status": "unknown"},
                    value={"capture": lambda_match.group("capture")},
                )
            for match in _ASSIGNMENT_RE.finditer(text):
                lhs = re.sub(r"\s+", "", match.group("lhs"))
                rhs = match.group("rhs").strip()
                if not lhs or not rhs:
                    continue
                is_origin = bool(_VALUE_ORIGIN_RE.search(rhs))
                is_member = lhs.startswith("this->") or lhs.startswith("this.") or lhs.endswith("_")
                if not is_origin and not is_member and rhs not in known_values:
                    continue
                kind = "member_write" if is_member else "value_assignment"
                fact_id = _fact(
                    facts,
                    seen,
                    kind=kind,
                    caller=function_id,
                    file_path=file_path,
                    line=line,
                    expression=text,
                    source="object_flow_source_scan",
                    evidence={
                        "file": file_path,
                        "start_line": line,
                        "end_line": line,
                        "text": text,
                    },
                    attributes={
                        "lhs": lhs,
                        "rhs": rhs,
                        "origin_kind": "factory_or_new" if is_origin else "local_value",
                    },
                    value={"variable": lhs, "origin": rhs, "origin_fact_id": known_values.get(rhs)},
                )
                known_values[lhs] = fact_id

            return_match = _RETURN_RE.search(text)
            if return_match:
                value = return_match.group("value").strip()
                value_key = re.sub(r"\s+", "", value)
                if value_key in known_values or _VALUE_ORIGIN_RE.search(value):
                    _fact(
                        facts,
                        seen,
                        kind="return_flow",
                        caller=function_id,
                        file_path=file_path,
                        line=line,
                        expression=text,
                        source="object_flow_source_scan",
                        evidence={
                            "file": file_path,
                            "start_line": line,
                            "end_line": line,
                            "text": text,
                        },
                        attributes={"returned_expression": value},
                        value={"variable": value_key, "origin_fact_id": known_values.get(value_key)},
                    )

            # Record a same-function transfer of a known value into a call
            # argument.  The callee is deliberately left unresolved here;
            # the regular ledger/Clang resolver supplies the target later.
            for call in _CALL_RE.finditer(text):
                args = call.group("args")
                transferred = [
                    variable
                    for variable in known_values
                    if re.search(rf"\b{re.escape(variable)}\b", args)
                ]
                if not transferred:
                    continue
                _fact(
                    facts,
                    seen,
                    kind="argument_value_flow",
                    caller=function_id,
                    file_path=file_path,
                    line=line,
                    expression=call.group(0).strip(),
                    source="object_flow_source_scan",
                    evidence={
                        "file": file_path,
                        "start_line": line,
                        "end_line": line,
                        "text": call.group(0).strip(),
                    },
                    attributes={"callee_spelling": call.group("callee"), "variables": transferred},
                    value={"variables": transferred},
                )


def _function_summary_facts(
    extract_result: Mapping[str, Any],
    diagnostics: Mapping[str, Any],
    facts: list[dict[str, Any]],
    seen: set[str],
) -> None:
    """Build bounded cross-function summaries from existing local facts.

    This is deliberately not a points-to solver.  It joins a call-site ledger
    record with same-file/source-line observations and the extracted parameter
    list.  The result says *which value was observed crossing a boundary*;
    it does not claim that every dynamic target or every execution path has
    been enumerated.
    """
    functions = extract_result.get("functions", {})
    if not isinstance(functions, Mapping):
        return
    local_by_location: dict[tuple[str, int], list[Mapping[str, Any]]] = {}
    source_by_caller: dict[str, list[Mapping[str, Any]]] = {}
    for item in facts:
        if item.get("source") not in {
            "object_flow_source_scan",
            "object_flow_cross_function_summary",
        }:
            continue
        caller = _text(item.get("caller_id"))
        line = item.get("line_start")
        try:
            line_key = int(line)
        except (TypeError, ValueError):
            continue
        local_by_location.setdefault((caller, line_key), []).append(item)
        source_by_caller.setdefault(caller, []).append(item)

    summaries_seen: set[str] = set()
    # One summary per function makes the available facts reusable by later
    # stages without forcing them to rescan every function body.
    for function_id, function in functions.items():
        if not isinstance(function_id, str) or not isinstance(function, Mapping):
            continue
        code = function.get("code")
        if not isinstance(code, str) or not code.strip():
            continue
        start = function.get("start_line", function.get("startLine", 1))
        try:
            start = int(start)
        except (TypeError, ValueError):
            start = 1
        related = source_by_caller.get(function_id, [])
        summary_line = start
        summary_id = _fact(
            facts,
            seen,
            kind="function_summary",
            caller=function_id,
            file_path=_text(function.get("file_path")),
            line=summary_line,
            expression=_text(function.get("name")) or function_id,
            source="object_flow_summary",
            evidence={
                "file": _text(function.get("file_path")),
                "start_line": summary_line,
                "end_line": summary_line,
                "text": _text(function.get("name")) or function_id,
            },
            attributes={
                "summary_kind": "local_value_flow",
                "parameter_count": len(_parameter_names(function)),
                "fact_count": len(related),
            },
            value={
                "parameters": _parameter_names(function),
                "fact_ids": [item.get("fact_id") for item in related if item.get("fact_id")],
            },
        )
        summaries_seen.add(summary_id)

    call_sites = diagnostics.get("call_sites")
    if not isinstance(call_sites, list):
        return
    for record in call_sites:
        if not isinstance(record, Mapping):
            continue
        caller = _text(record.get("caller_id"))
        if not caller or caller not in functions:
            continue
        line = record.get("line_start")
        try:
            line_key = int(line)
        except (TypeError, ValueError):
            continue
        expression = _text(record.get("expression"))
        if not expression:
            continue
        # Reuse the same owner-qualified narrowing used by the candidate
        # overlay.  Cross-function summaries must not multiply a single call
        # by every same-named singleton in the repository.
        _, candidates = _refine_candidate_targets(record, functions)
        if not candidates:
            candidates = [
                _normal_endpoint(item)
                for item in _list(record.get("linked_target_ids"))
                if _normal_endpoint(item)
            ]
        candidates = list(dict.fromkeys(candidates))
        if not candidates:
            continue
        line_text = _line_for_function(functions[caller], line)
        local_items = local_by_location.get((caller, line_key), [])
        transferred: list[str] = []
        for item in local_items:
            if item.get("fact_kind") == "argument_value_flow":
                transferred.extend(_text(value) for value in _list(item.get("value", {}).get("variables")))
        transferred = list(dict.fromkeys(value for value in transferred if value))
        args_match = re.search(r"\((?P<args>.*)\)$", expression)
        args = _split_arguments(args_match.group("args")) if args_match else []
        if not transferred:
            transferred = [
                value
                for value in args
                if re.fullmatch(r"[A-Za-z_]\w*", value)
            ]
        assignment_items = [
            item for item in local_items
            if item.get("fact_kind") in {"value_assignment", "member_write"}
            and _text(item.get("value", {}).get("origin"))
            and (
                _text(record.get("callee_spelling")) in _text(item.get("value", {}).get("origin"))
                or _text(record.get("callee_spelling")) in line_text
            )
        ]
        return_items = [
            item for item in local_items
            if item.get("fact_kind") == "return_flow"
            and (_text(record.get("callee_spelling")) in line_text or expression in line_text)
        ]
        callee_spelling = _text(record.get("callee_spelling"))
        result_consumed_in_source = bool(
            callee_spelling
            and callee_spelling in line_text
            and (
                re.search(r"\breturn\b", line_text)
                or re.search(r"\b[A-Za-z_]\w*\s*=", line_text)
            )
        )
        for target in candidates:
            target_function = functions.get(target)
            target_parameters = _parameter_names(target_function) if isinstance(target_function, Mapping) else []
            parameter_pairs = []
            for index, value in enumerate(args):
                if index < len(target_parameters) and (
                    value in transferred or re.fullmatch(r"[A-Za-z_]\w*", value or "")
                ):
                    parameter_pairs.append({
                        "index": index,
                        "caller_expression": value,
                        "callee_parameter": target_parameters[index],
                    })
            if transferred or parameter_pairs:
                _fact(
                    facts,
                    seen,
                    kind="cross_function_argument_flow",
                    caller=caller,
                    target=target,
                    file_path=_text(record.get("file")),
                    line=line,
                    expression=expression,
                    source="object_flow_cross_function_summary",
                    evidence={
                        "file": _text(record.get("file")),
                        "start_line": line,
                        "end_line": record.get("line_end", line),
                        "text": expression,
                        "site_id": record.get("site_id", ""),
                    },
                    attributes={
                        "call_site_id": record.get("site_id", ""),
                        "candidate_completeness": record.get("candidate_completeness", "unknown"),
                        "argument_pairs": parameter_pairs,
                        "summary_status": "candidate",
                    },
                    value={"variables": transferred, "argument_pairs": parameter_pairs},
                )
            if assignment_items or return_items or result_consumed_in_source:
                _fact(
                    facts,
                    seen,
                    kind="cross_function_return_flow",
                    caller=caller,
                    target=target,
                    file_path=_text(record.get("file")),
                    line=line,
                    expression=expression,
                    source="object_flow_cross_function_summary",
                    evidence={
                        "file": _text(record.get("file")),
                        "start_line": line,
                        "end_line": record.get("line_end", line),
                        "text": line_text or expression,
                        "site_id": record.get("site_id", ""),
                    },
                    attributes={
                        "call_site_id": record.get("site_id", ""),
                        "assignment_fact_ids": [item.get("fact_id") for item in assignment_items],
                        "return_fact_ids": [item.get("fact_id") for item in return_items],
                        "summary_status": "candidate",
                    },
                    value={
                        "callee_spelling": record.get("callee_spelling", ""),
                        "result_consumed": bool(
                            assignment_items or return_items or result_consumed_in_source
                        ),
                    },
                )


def _callback_registry_dispatch_facts(
    extract_result: Mapping[str, Any],
    facts: list[dict[str, Any]],
    seen: set[str],
) -> None:
    """Connect map-backed callback dispatchers to registered callbacks.

    A common OpenHarmony pattern registers lambdas in an object-owned map and
    later executes ``map[key]()`` (or an equivalent iterator call).  The
    parser can see both sides but a conventional call graph cannot represent
    the runtime lookup.  This pass creates *candidate* edges only, retaining
    the registration and dispatcher source evidence.  It scopes the relation
    to the same source file and owner class so an unrelated map or same-named
    method cannot be joined by name alone.
    """
    functions = extract_result.get("functions", {})
    if not isinstance(functions, Mapping):
        return

    def owner_of(function_id: str) -> str:
        name = function_id.split(":", 1)[1] if ":" in function_id else function_id
        if "::" not in name:
            return ""
        return name.rsplit("::", 1)[0].rsplit("::", 1)[-1]

    registrations: dict[tuple[str, str], set[str]] = {}
    registry_names: dict[tuple[str, str], set[str]] = {}
    for fact in facts:
        if not isinstance(fact, Mapping):
            continue
        caller = _text(fact.get("caller_id"))
        target = _text(fact.get("target_id"))
        if not caller or not target:
            continue
        caller_name = caller.split(":", 1)[1] if ":" in caller else caller
        target_name = target.split(":", 1)[1] if ":" in target else target
        # AddCapture/constructor registration records are emitted by the
        # ledger and source scanner.  Only same-owner callback methods are
        # eligible; constructor direct calls are not dynamic dispatch.
        if not caller_name.endswith("::AddCapture"):
            continue
        if "::" not in target_name:
            continue
        function = functions.get(caller)
        if not isinstance(function, Mapping):
            continue
        file_path = _text(function.get("file_path"))
        owner = owner_of(caller)
        target_owner = owner_of(target)
        if not file_path or not owner or target_owner != owner:
            continue
        registrations.setdefault((file_path, owner), set()).add(target)
        code = _text(function.get("code"))
        for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\.insert\s*\(", code):
            registry_names.setdefault((file_path, owner), set()).add(match.group(1))

    if not registrations:
        return

    for caller, function in functions.items():
        if not isinstance(caller, str) or not isinstance(function, Mapping):
            continue
        file_path = _text(function.get("file_path"))
        owner = owner_of(caller)
        targets = registrations.get((file_path, owner))
        known_registries = registry_names.get((file_path, owner), set())
        if not targets or not known_registries or not isinstance(function.get("code"), str):
            continue
        code = function.get("code") or ""
        # Require both lookup and invocation syntax. A mere map insertion or
        # lookup without a call is not an execution edge.
        dispatch_lines: list[tuple[int, str]] = []
        start_line = function.get("start_line", function.get("startLine", 1))
        try:
            start_line = int(start_line)
        except (TypeError, ValueError):
            start_line = 1
        pending_lookup = False
        pending_lookup_line = 0
        for offset, raw_line in enumerate(code.splitlines()):
            line = raw_line.strip()
            if not line:
                continue
            lookup = any(
                f"{registry}.find(" in line or f"{registry}.find (" in line
                for registry in known_registries
            )
            invocation = (
                any(f"{registry}[" in line for registry in known_registries)
                and ("()" in line or "->second()" in line or ".second()" in line)
                or "->second()" in line
                or ".second()" in line
                or "it->second" in line
            )
            if lookup:
                pending_lookup = True
                pending_lookup_line = start_line + offset
            if pending_lookup and invocation:
                # Use the actual invocation line as the call-site evidence;
                # retain the lookup line as a diagnostic attribute below.
                dispatch_lines.append((start_line + offset, line))
                pending_lookup = False
            elif pending_lookup and start_line + offset - pending_lookup_line > 3:
                pending_lookup = False
        if not dispatch_lines:
            continue
        for line, expression in dispatch_lines:
            for target in sorted(targets):
                _fact(
                    facts,
                    seen,
                    kind="callback_registry_dispatch",
                    caller=caller,
                    target=target,
                    file_path=file_path,
                    line=line,
                    expression=expression,
                    source="object_flow_callback_registry",
                    evidence={
                        "file": file_path,
                        "start_line": line,
                        "end_line": line,
                        "text": expression,
                    },
                    attributes={
                        "dispatch_type": "map_function_object",
                        "registry_owner": owner,
                        "registration_scope": "same_owner_same_file",
                        "candidate_completeness": "bounded_same_owner_registry",
                        "execution_relation": "key_selected_callback_invocation",
                    },
                    value={"registered_targets": sorted(targets)},
                )


def build_object_flow_facts(
    extract_result: Mapping[str, Any],
    diagnostics: Mapping[str, Any] | None = None,
    call_graph_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """从已有诊断和调用点记录构造候选对象/值流事实。

    ``diagnostics`` 是主要输入；调用图只用于保存版本和补充已存在的 caller
    集合。函数不会修改任一输入，也不会把候选关系写入 native 图。
    """
    diagnostics = diagnostics if isinstance(diagnostics, Mapping) else {}
    functions = extract_result.get("functions", {})
    if not isinstance(functions, Mapping):
        functions = {}
    repository = _text(extract_result.get("repository"))
    revision = _text(
        extract_result.get("revision")
        or extract_result.get("commit_sha")
        or extract_result.get("source_revision")
        or "unknown"
    ) or "unknown"
    build_status = _text(
        extract_result.get("build_status")
        or extract_result.get("build_context_status")
        or "unknown"
    ) or "unknown"
    facts: list[dict[str, Any]] = []
    seen: set[str] = set()
    overlay_edges: list[dict[str, Any]] = []
    edge_seen: set[tuple[str, str, str]] = set()
    symbol_nodes: list[dict[str, Any]] = []
    symbol_seen: set[str] = set()

    def add_symbol_node(
        node_id: Any,
        *,
        status: str = "declaration_only",
        source: str = "object_flow_facts",
        evidence: Mapping[str, Any] | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> None:
        node_id = _normal_endpoint(node_id)
        if not node_id or node_id in symbol_seen:
            return
        symbol_seen.add(node_id)
        symbol_nodes.append(
            {
                "id": node_id,
                "attributes": {
                    "node_kind": "function_symbol",
                    "symbol_status": status,
                    "source": source,
                    "candidate_only": True,
                    **dict(attributes or {}),
                },
                "evidence": dict(evidence or {}),
            }
        )


    def add_edge(
        fact_id: str,
        caller: str,
        target: str,
        *,
        file_path: str,
        line: Any,
        expression: str,
        fact_kind: str,
    ) -> None:
        caller = _normal_endpoint(caller)
        target = _normal_endpoint(target)
        if not caller or not target:
            return
        key = (caller, target, fact_id)
        if key in edge_seen:
            return
        edge_seen.add(key)
        overlay_edges.append(
            {
                "source_id": caller,
                "target_id": target,
                "resolver": "openharmony_object_flow",
                "status": "candidate",
                "site_id": fact_id,
                "kind": fact_kind,
                "evidence": {
                    "file": file_path,
                    "start_line": line,
                    "end_line": line,
                    "expression": expression,
                },
                "attributes": {
                    "source_revision": revision,
                    "build_status": build_status,
                    "candidate_completeness": "unknown",
                    "evidence_quality": "syntax_observation",
                    "reachability_tier": "candidate",
                    "strict_admission": False,
                    "fact_id": fact_id,
                },
            }
        )

    # Explicit registration records already carry the most useful source
    # evidence: table, selector, target and the registration expression.
    for record in _list(diagnostics.get("dispatch_assignments")):
        if not isinstance(record, Mapping):
            continue
        caller = _text(record.get("owner_function_id"))
        target = _text(record.get("target_id"))
        file_path = _text(record.get("file"))
        line = record.get("line")
        expression = _text(record.get("evidence", {}).get("text") if isinstance(record.get("evidence"), Mapping) else "")
        if not expression:
            expression = f"{record.get('table', '')}[{record.get('selector', '')}]"
        fact_id = _fact(
            facts,
            seen,
            kind="dispatch_registration",
            caller=caller,
            target=target,
            file_path=file_path,
            line=line,
            expression=expression,
            source="call_graph_diagnostics.dispatch_assignments",
            evidence=_evidence(record, file_path=file_path, line=line, expression=expression),
            attributes={
                "table": record.get("table", ""),
                "selector": record.get("selector", ""),
                "value_kind": record.get("value_kind", ""),
                "registration_form": record.get("registration_form", "assignment"),
                "resolution": record.get("resolution", ""),
            },
            value={"target_name": record.get("target_name", ""), "target_id": target or None},
        )
        add_edge(fact_id, caller, target, file_path=file_path, line=line, expression=expression, fact_kind="dispatch_registration")

    lambda_payload = diagnostics.get("lambda_dispatch")
    if isinstance(lambda_payload, Mapping):
        for record in _list(lambda_payload.get("assignments")):
            if not isinstance(record, Mapping):
                continue
            caller = _text(record.get("owner_function_id"))
            target = _text(record.get("target_id"))
            file_path = _text(record.get("file"))
            line = record.get("line")
            expression = _text(record.get("evidence", {}).get("text") if isinstance(record.get("evidence"), Mapping) else "")
            fact_id = _fact(
                facts,
                seen,
                kind="callback_registration",
                caller=caller,
                target=target,
                file_path=file_path,
                line=line,
                expression=expression,
                source="call_graph_diagnostics.lambda_dispatch.assignments",
                evidence=_evidence(record, file_path=file_path, line=line, expression=expression),
                attributes={
                    "table": record.get("table", ""),
                    "selector": record.get("selector", ""),
                    "capture": record.get("capture", ""),
                    "lambda_calls": record.get("lambda_calls", []),
                    "registration_form": record.get("registration_form", ""),
                },
                value={"target_name": record.get("target_name", ""), "target_id": target or None},
            )
            add_edge(fact_id, caller, target, file_path=file_path, line=line, expression=expression, fact_kind="callback_registration")

    for record in _list(diagnostics.get("parameter_flows")):
        if not isinstance(record, Mapping):
            continue
        caller = _text(record.get("source_function_id"))
        target = _text(record.get("callee_id"))
        evidence = record.get("evidence") if isinstance(record.get("evidence"), Mapping) else {}
        file_path = _text(evidence.get("file"))
        line = evidence.get("start_line")
        expression = _text(evidence.get("text"))
        fact_id = _fact(
            facts,
            seen,
            kind="parameter_flow",
            caller=caller,
            target=target,
            file_path=file_path,
            line=line,
            expression=expression,
            source="call_graph_diagnostics.parameter_flows",
            evidence=dict(evidence),
            attributes={
                "argument_index": record.get("argument_index"),
                "source_table": record.get("source_table", ""),
                "callee_parameter": record.get("callee_parameter", ""),
                "registration_form": record.get("registration_form", ""),
                "resolution": record.get("resolution", ""),
            },
            value={
                "source_table": record.get("source_table", ""),
                "callee_parameter": record.get("callee_parameter", ""),
            },
        )
        # A parameter-flow record relates the caller to the callee, but is not
        # itself an executable call edge; keep it in facts only.
        _ = fact_id

    for record in _list(diagnostics.get("unresolved_call_sites")):
        if not isinstance(record, Mapping):
            continue
        caller = _text(record.get("caller_id"))
        file_path = _text(record.get("file"))
        line = record.get("line")
        expression = _text(record.get("expression"))
        raw_candidates, candidates = _refine_candidate_targets(record, functions)
        for target in raw_candidates:
            if target not in functions:
                add_symbol_node(
                    target,
                    status="declaration_only",
                    source="call_graph_diagnostics.unresolved_call_sites",
                    evidence=_evidence(record, file_path=file_path, line=line, expression=expression),
                    attributes={"candidate_completeness": record.get("candidate_completeness", "unknown")},
                )
        fact_id = _fact(
            facts,
            seen,
            kind="indirect_call_site",
            caller=caller,
            file_path=file_path,
            line=line,
            expression=expression,
            source="call_graph_diagnostics.unresolved_call_sites",
            evidence=_evidence(record, file_path=file_path, line=line, expression=expression),
            attributes={
                "reason": record.get("reason", ""),
                "ast_kind": record.get("ast_kind", ""),
                "candidate_count": len(candidates),
                "raw_candidate_count": len(raw_candidates),
                "candidate_completeness": record.get("candidate_completeness", "unknown"),
                "symbols": record.get("symbols", {}),
            },
            value={
                "candidate_target_ids": candidates,
                "raw_candidate_target_ids": raw_candidates,
            },
        )
        for target in candidates:
            add_edge(fact_id, caller, target, file_path=file_path, line=line, expression=expression, fact_kind="indirect_call_site")

    # The call-site ledger contains ordinary member/direct calls that have a
    # bounded candidate target but no strict graph edge.  Keep these as
    # candidate value-flow observations, and mark factory-like expressions so
    # later object-flow passes can prioritize them.
    for record in _list(diagnostics.get("call_sites")):
        if not isinstance(record, Mapping):
            continue
        raw_candidates, candidates = _refine_candidate_targets(record, functions)
        for target in raw_candidates:
            if target not in functions:
                add_symbol_node(
                    target,
                    status="declaration_only",
                    source="call_graph_diagnostics.call_sites",
                    evidence={
                        "file": _text(record.get("file")),
                        "start_line": record.get("line_start"),
                        "end_line": record.get("line_end", record.get("line_start")),
                        "text": _text(record.get("expression")),
                        "site_id": record.get("site_id", ""),
                    },
                    attributes={"candidate_completeness": record.get("candidate_completeness", "unknown")},
                )
        if not candidates:
            continue
        graph_status = _text(record.get("graph_status"))
        binding_status = _text(record.get("binding_status"))
        # A parser-linked direct call is already represented by the native
        # graph.  Keep it out of the first candidate overlay; otherwise the
        # object-flow layer merely duplicates thousands of ordinary edges.
        if graph_status == "linked" and _text(record.get("call_kind")) != "indirect":
            continue
        if graph_status not in {"edge_missing", "candidate_or_dynamic"} and binding_status not in {"partial", "unresolved"}:
            continue
        kind = "factory_value_flow" if _is_factory_expression(_text(record.get("expression"))) else "call_site_candidate"
        caller = _text(record.get("caller_id"))
        file_path = _text(record.get("file"))
        line = record.get("line_start")
        expression = _text(record.get("expression"))
        fact_id = _fact(
            facts,
            seen,
            kind=kind,
            caller=caller,
            file_path=file_path,
            line=line,
            expression=expression,
            source="call_graph_diagnostics.call_sites",
            evidence={
                "file": file_path,
                "start_line": line,
                "end_line": record.get("line_end", line),
                "text": expression,
                "site_id": record.get("site_id", ""),
            },
            attributes={
                "call_kind": record.get("call_kind", ""),
                "callee_spelling": record.get("callee_spelling", ""),
                "graph_status": graph_status,
                "binding_status": binding_status,
                "candidate_completeness": record.get("candidate_completeness", "unknown"),
                "candidate_target_count": len(candidates),
                "raw_candidate_target_count": len(raw_candidates),
            },
            value={
                "candidate_target_ids": candidates,
                "raw_candidate_target_ids": raw_candidates,
            },
        )
        for target in candidates:
            add_edge(fact_id, caller, target, file_path=file_path, line=line, expression=expression, fact_kind=kind)

    _source_value_flow_facts(extract_result, facts, seen)
    # Map-backed callback registries (for example EventLogTask::captureList_)
    # have no ordinary static call edge from their dispatcher to the lambda
    # target.  Add auditable candidate facts before the cross-function summary
    # pass so later graph construction and context generation can consume the
    # same evidence.
    _callback_registry_dispatch_facts(extract_result, facts, seen)
    _function_summary_facts(extract_result, diagnostics, facts, seen)
    for item in facts:
        if item.get("source") not in {
            "object_flow_source_scan",
            "object_flow_cross_function_summary",
            "object_flow_callback_registry",
        }:
            continue
        caller = _text(item.get("caller_id"))
        target = _text(item.get("target_id"))
        if caller and target:
            add_edge(
                _text(item.get("fact_id")),
                caller,
                target,
                file_path=_text(item.get("file")),
                line=item.get("line_start"),
                expression=_text(item.get("expression")),
                fact_kind=_text(item.get("fact_kind")) or "object_flow",
            )
        for target in _list(item.get("attributes", {}).get("target_candidates")):
            if _normal_endpoint(target) not in functions:
                add_symbol_node(
                    target,
                    status="declaration_only",
                    source=_text(item.get("source")) or "object_flow_facts",
                    evidence=item.get("evidence") if isinstance(item.get("evidence"), Mapping) else {},
                    attributes={"fact_id": item.get("fact_id"), "fact_kind": item.get("fact_kind")},
                )

    facts.sort(key=lambda item: (item.get("file", ""), item.get("line_start") or 0, item.get("fact_kind", ""), item.get("fact_id", "")))
    overlay_edges.sort(key=lambda item: (item.get("source_id", ""), item.get("target_id", ""), item.get("site_id", "")))
    counts = Counter(item.get("fact_kind", "unknown") for item in facts)
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "platform": "openharmony",
        "status": "complete",
        "repository": repository,
        "source_revision": revision,
        "build_status": build_status,
        "facts": facts,
        "candidate_overlay": {
            "schema_version": SCHEMA_VERSION,
            "graph_type": OVERLAY_TYPE,
            "status": "candidate_only",
            "repository": repository,
            "source_revision": revision,
            "build_status": build_status,
            "implementation_version": IMPLEMENTATION_VERSION,
            "nodes": symbol_nodes,
            "edges": overlay_edges,
        },
        "symbol_nodes": symbol_nodes,
        "function_summaries": [
            item for item in facts if item.get("fact_kind") == "function_summary"
        ],
        "summary": {
            "fact_count": len(facts),
            "candidate_edge_count": len(overlay_edges),
            "facts_by_kind": dict(sorted(counts.items())),
            "functions_in_index": len(functions),
            "call_graph_available": isinstance(call_graph_result, Mapping),
            "strict_edges_added": 0,
            "strict_admission": "never_from_object_flow_candidate_facts",
            "symbol_node_count": len(symbol_nodes),
            "cross_function_fact_count": sum(
                1
                for item in facts
                if str(item.get("fact_kind", "")).startswith("cross_function_")
            ),
            "function_summary_count": sum(
                1 for item in facts if item.get("fact_kind") == "function_summary"
            ),
        },
        "provenance": {
            "diagnostics": "call_graph_residuals.json",
            "call_graph": "call_graph.json" if isinstance(call_graph_result, Mapping) else None,
            "resolver": "openharmony_object_flow_facts_v2",
            "implementation_version": IMPLEMENTATION_VERSION,
        },
    }


__all__ = [
    "IMPLEMENTATION_VERSION",
    "OVERLAY_TYPE",
    "REPORT_TYPE",
    "SCHEMA_VERSION",
    "build_object_flow_facts",
]
