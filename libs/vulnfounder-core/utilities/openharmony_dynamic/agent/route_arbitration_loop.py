"""候选入口路由复核 Agent Loop。

入口发现会把同一服务的多个端点全部保留下来；本模块只在当前 finding 没有
明确端点、且候选不止一个时工作，比较候选与目标 sink 的源码证据。它不能
凭端口号、候选顺序或服务名称选择路由：模型必须提交一个候选 ID、真实源码
引用和理由；证据不足时返回 deferred，由上层保持 REQUIRES_PROTOCOL_REVIEW。

该 loop 不生成协议字段、攻击载荷或设备写命令，也不改变候选的原始
route_relevance。选中的 possible 路由仍然带着不确定性进入后续协议编译，
最终是否 ELIGIBLE 继续由描述符和契约校验决定。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .entry_discovery_loop import EntryCandidate, _source_ref_valid
from .recon_loop import _parse_action
from .recon_tools import ReconTools


_MAX_TURNS_DEFAULT = 6
_MAX_EVIDENCE = 12


ROUTE_ARBITRATION_SYSTEM_PROMPT = (
    "你是 OpenHarmony 动态测试的候选入口路由复核器。目标是为当前 finding "
    "在已发现的多个入口候选中判断是否存在一条最有源码证据支持的路由。\n"
    "每轮只输出一个 JSON 动作：\n"
    '{"tool":"read_file","args":{"path":"...","offset":0,"limit":200}}\n'
    '{"tool":"grep","args":{"pattern":"...","path":"."}}\n'
    '{"tool":"list_dir","args":{"path":"."}}\n'
    '{"tool":"finalize","args":{"decision":"select|defer",'
    '"selected_candidate_id":"entry-...",'
    '"evidence":["path/to/file.cpp:10-20"],'
    '"rejected":[{"candidate_id":"entry-...","reason":"..."}],'
    '"reason":"..."}}\n'
    "工具只能读取当前仓库源码；不要执行设备写入、启动、停止、安装、注入、"
    "协议发送或破坏性命令。\n"
    "硬规则：\n"
    "1. 只能选择给定 candidates 中的 candidate_id，不能创造端点或改写候选。\n"
    "2. selected_candidate_id 必须与当前 finding 的 target_sink 有源码关系；"
    "仅有 bind/listen/recv 证据不能证明业务分派。\n"
    "3. evidence 必须引用仓库内真实存在的源码区间，并应说明 handler、分派条件、"
    "对象/状态关系或 sink 调用中的至少一项。\n"
    "4. 如果两个或多个候选仍然同样合理，必须 decision=defer；不要按端口大小、"
    "候选顺序或熟悉的协议名称猜测。\n"
    "5. finalize 前至少读取或 grep 一次源码。只输出 JSON，不要附加解释文字。"
)


@dataclass
class RouteArbitrationResult:
    status: str = ""  # selected | deferred | llm_unavailable | budget_exhausted
    selected_candidate_id: str = ""
    evidence: list[str] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)
    reason: str = ""
    turns_used: int = 0
    audit: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "selected_candidate_id": self.selected_candidate_id,
            "evidence": list(self.evidence),
            "rejected": list(self.rejected),
            "reason": self.reason,
            "turns_used": self.turns_used,
            "audit": list(self.audit),
            "error": self.error,
        }


def _candidate_dict(candidate: Any) -> dict[str, Any]:
    converter = getattr(candidate, "to_dict", None)
    if callable(converter):
        try:
            value = converter()
            if isinstance(value, dict):
                return value
        except Exception:  # noqa: BLE001 - 审计上下文序列化失败不阻断复核
            pass
    if isinstance(candidate, dict):
        return dict(candidate)
    return {
        key: getattr(candidate, key, "")
        for key in (
            "kind", "endpoint", "hint", "confidence", "candidate_id",
            "route_relevance", "handler", "target_sink", "dispatch_conditions",
            "state_flow", "source_evidence", "route_evidence", "reason",
        )
    }


def _candidate_by_id(candidates: list[Any], candidate_id: str) -> Any | None:
    wanted = str(candidate_id or "").strip()
    if not wanted:
        return None
    for candidate in candidates:
        if str(getattr(candidate, "candidate_id", "")) == wanted:
            return candidate
        if isinstance(candidate, dict) and str(candidate.get("candidate_id", "")) == wanted:
            return candidate
    return None


def _valid_evidence(repo_root: Path, values: Any) -> tuple[list[str], list[str]]:
    if not isinstance(values, list):
        return [], ["evidence 必须是字符串数组"]
    accepted: list[str] = []
    errors: list[str] = []
    for raw in values[:_MAX_EVIDENCE]:
        if not isinstance(raw, str) or not raw.strip():
            continue
        ref = raw.strip()
        if _source_ref_valid(repo_root, ref):
            accepted.append(ref)
        else:
            errors.append(f"源码证据无法核验: {ref}")
    return list(dict.fromkeys(accepted)), errors


def _route_references(candidate: Any) -> set[str]:
    refs: set[str] = set()
    for key in ("source_evidence", "route_evidence"):
        value = getattr(candidate, key, None)
        if isinstance(value, list):
            refs.update(str(x).strip() for x in value if str(x).strip())
    return refs


def _source_path(reference: str) -> str:
    match = re.match(r"^(.*?):\d+(?:-\d+)?$", str(reference).strip())
    return match.group(1) if match else str(reference).strip()


def _source_window(reference: str) -> tuple[str, int]:
    match = re.match(r"^(.*?):(\d+)(?:-\d+)?$", str(reference).strip())
    if not match:
        return str(reference).strip(), 0
    return match.group(1), max(0, int(match.group(2)) - 1)


def run_route_arbitration_loop(
    *,
    finding: Any,
    candidates: list[Any],
    repo_root: Path,
    binding_pair=None,
    max_turns: int = _MAX_TURNS_DEFAULT,
    on_event=None,
) -> RouteArbitrationResult:
    """比较当前 finding 的多个入口候选，必要时选择一条可审计路由。"""

    result = RouteArbitrationResult()
    if binding_pair is None:
        result.status = "llm_unavailable"
        result.error = "候选路由复核 Agent Loop 的 LLM 不可用"
        return result
    if len(candidates) < 2:
        result.status = "deferred"
        result.reason = "候选数量不足，无需执行路由复核"
        return result

    binding, simple_text = binding_pair
    tools = ReconTools(hdc=None, repo_root=repo_root)
    finding_dict = (
        finding.to_prompt_dict()
        if hasattr(finding, "to_prompt_dict")
        else finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
    )
    # 只把当前候选及其证据交给模型；不加载历史事实、exemplar 或设备资产。
    context = [
        "当前 finding:", json.dumps(finding_dict, ensure_ascii=False, indent=2)[:12000],
        "当前候选入口（只能从这里选择，候选顺序没有优先级）:",
        json.dumps([_candidate_dict(c) for c in candidates], ensure_ascii=False, indent=2)[:24000],
        "仓库根目录:", str(repo_root),
        "请先阅读与候选 handler/分派/sink 相关的源码，再决定 select 或 defer。",
    ]
    transcript: list[str] = []
    action_keys: set[str] = set()
    evidence_actions = 0
    loop_audit: list[dict[str, Any]] = []

    def emit(turn: int, kind: str, tool: str = "", args: Any = None, out: Any = None,
             note: str = "") -> None:
        record: dict[str, Any] = {"turn": turn, "max_turns": max_turns, "kind": kind}
        if tool:
            record["tool"] = tool
        if isinstance(args, dict) and args:
            record["args"] = {k: str(v)[:160] for k, v in list(args.items())[:4]}
        if isinstance(out, dict):
            record["ok"] = bool(out.get("ok", True))
            summary = str(out.get("output", out.get("error", "")))[:400]
            if summary:
                record["output"] = summary
        if note:
            record["note"] = note[:400]
        loop_audit.append(dict(record))
        if on_event is None:
            return
        try:
            on_event({
                "event": "route_arbitration_turn",
                "detail": f"候选路由复核第 {turn} 轮：{kind}" + (f" {tool}" if tool else ""),
                "record": record,
            })
        except Exception:  # noqa: BLE001
            pass

    # 复核 loop 的第一轮如果直接 finalize，不能让“必须先取证”的门禁白白
    # 消耗预算。候选已经携带了入口/路由源码引用，因此可安全地预读每个
    # 候选至多两个不同源码文件的有限窗口；这不是全仓规则检索，也不会把
    # 预读结果升级成选择结论，模型仍须比较候选并提交 evidence。
    bootstrap_refs: list[str] = []
    for candidate in candidates:
        for key in ("route_evidence", "source_evidence"):
            for reference in list(getattr(candidate, key, []) or []):
                ref = str(reference).strip()
                if ref and ref not in bootstrap_refs:
                    bootstrap_refs.append(ref)
    bootstrap_paths: list[tuple[str, int]] = []
    seen_paths: set[str] = set()
    for reference in bootstrap_refs:
        path, offset = _source_window(reference)
        if path in seen_paths:
            continue
        seen_paths.add(path)
        bootstrap_paths.append((path, offset))
        if len(bootstrap_paths) >= min(6, max(2, len(candidates) * 2)):
            break
    for path, offset in bootstrap_paths:
        out = tools.call("read_file", {"path": path, "offset": offset, "limit": 120})
        if not out.get("ok"):
            continue
        evidence_actions += 1
        emit(0, "bootstrap", "read_file", {
            "path": path, "offset": offset, "limit": 120,
        }, out, note="候选已声明源码窗口预读")
        transcript.append(
            f"[bootstrap] read_file {path}:{offset}\n"
            f"→ {json.dumps(out, ensure_ascii=False)[:3500]}"
        )

    for turn in range(1, max(1, int(max_turns)) + 1):
        result.turns_used = turn
        prompt = "\n".join([
            *context,
            "已执行动作:", *transcript[-6:],
            f"候选路由复核轮次 {turn}/{max_turns}；只输出一个 JSON 动作:",
        ])
        if turn >= max(1, int(max_turns)) - 1:
            prompt += ("\n⚠️ 收敛阶段：若已有足够源码证据就 finalize；若仍有两个候选同样合理，"
                       "必须 defer，不要猜测。")
        try:
            text = simple_text(binding, prompt, system=ROUTE_ARBITRATION_SYSTEM_PROMPT,
                               max_tokens=10000)
        except Exception as exc:  # noqa: BLE001
            result.status = "llm_unavailable"
            result.error = f"LLM 调用失败: {type(exc).__name__}: {str(exc)[:300]}"
            break
        action = _parse_action(str(text))
        if action is None:
            transcript.append(f"[turn {turn}] 非法 JSON 输出，已忽略")
            emit(turn, "invalid", note="LLM 输出不是可执行 JSON")
            continue
        tool, args = action["tool"], action["args"]
        action_key = json.dumps([tool, args], ensure_ascii=False, sort_keys=True)
        if action_key in action_keys and tool != "finalize":
            transcript.append(f"[turn {turn}] 重复动作已拒绝：{tool}；请读取新证据或 finalize")
            emit(turn, "duplicate", tool, args, note="该动作已经执行过")
            continue
        action_keys.add(action_key)
        if tool == "finalize":
            if evidence_actions == 0:
                transcript.append(f"[turn {turn}] finalize 被拒：尚未读取源码")
                emit(turn, "gate", tool, args, note="需先执行源码取证")
                continue
            decision = str(args.get("decision", "defer")).strip().lower()
            if decision not in {"select", "defer"}:
                transcript.append(f"[turn {turn}] decision 非法: {decision!r}")
                emit(turn, "invalid", tool, args, note="decision 只能是 select/defer")
                continue
            selected_id = str(args.get("selected_candidate_id", "")).strip()
            selected = _candidate_by_id(candidates, selected_id)
            evidence, evidence_errors = _valid_evidence(repo_root, args.get("evidence") or [])
            if evidence_errors:
                transcript.append(f"[turn {turn}] evidence 校验失败: {'；'.join(evidence_errors[:3])}")
                emit(turn, "invalid", tool, args, note="；".join(evidence_errors[:3]))
                continue
            rejected = args.get("rejected") or []
            if not isinstance(rejected, list):
                rejected = []
            normalized_rejected: list[dict[str, str]] = []
            for item in rejected[: len(candidates)]:
                if not isinstance(item, dict):
                    continue
                cid = str(item.get("candidate_id", "")).strip()
                if _candidate_by_id(candidates, cid) is not None and cid != selected_id:
                    normalized_rejected.append({
                        "candidate_id": cid,
                        "reason": str(item.get("reason", ""))[:500],
                    })
            if decision == "select":
                if selected is None:
                    transcript.append(f"[turn {turn}] selected_candidate_id 不在候选集合")
                    emit(turn, "invalid", tool, args, note="候选 ID 不存在")
                    continue
                relevance = str(getattr(selected, "route_relevance", "unknown"))
                if relevance == "unrelated":
                    transcript.append(f"[turn {turn}] 选择了 unrelated 候选")
                    emit(turn, "invalid", tool, args, note="unrelated 候选不可选择")
                    continue
                # 复核必须提供能够区分候选的证据；仅重复 endpoint/bind 位置不足以
                # 证明 sink 分派。要求至少一条新证据，并且不能完全脱离候选已知
                # 的源码范围，避免模型用其它服务文件强行拼接路由。
                known = _route_references(selected)
                if not evidence:
                    transcript.append(f"[turn {turn}] select 缺少可核验源码证据")
                    emit(turn, "invalid", tool, args, note="select 至少需要一条源码证据")
                    continue
                known_paths = {_source_path(ref) for ref in known}
                evidence_paths = {_source_path(ref) for ref in evidence}
                if known and not (evidence_paths & known_paths):
                    transcript.append(f"[turn {turn}] select 证据未与候选源码范围交集")
                    emit(turn, "invalid", tool, args, note="证据未落在选中候选的源码文件范围")
                    continue
                result.status = "selected"
                result.selected_candidate_id = selected_id
                result.evidence = evidence
                result.rejected = normalized_rejected
                result.reason = str(args.get("reason", ""))[:1000]
            else:
                result.status = "deferred"
                result.evidence = evidence
                result.rejected = normalized_rejected
                result.reason = str(args.get("reason", "仍有多个候选无法区分"))[:1000]
            emit(turn, "finalize", tool, args,
                 note=f"{result.status}: {result.selected_candidate_id or '不选择'}")
            break
        out = tools.call(tool, args)
        if tool in {"read_file", "grep", "list_dir"} and out.get("ok"):
            evidence_actions += 1
        emit(turn, "tool", tool, args, out)
        transcript.append(
            f"[turn {turn}] {tool} {json.dumps(args, ensure_ascii=False)[:400]}\n"
            f"→ {json.dumps(out, ensure_ascii=False)[:3500]}"
        )
    else:
        result.status = "budget_exhausted"
        result.error = f"{max_turns} 轮未 finalize"
    result.audit = [*loop_audit, *[a.to_dict() for a in tools.audit]]
    if not result.status:
        result.status = "budget_exhausted"
        result.error = result.error or f"{max_turns} 轮未完成候选路由复核"
    return result


__all__ = [
    "ROUTE_ARBITRATION_SYSTEM_PROMPT",
    "RouteArbitrationResult",
    "run_route_arbitration_loop",
]
