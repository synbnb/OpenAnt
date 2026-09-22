"""外部入口发现 Agent Loop。

该 loop 位于协议描述符匹配之前。它的职责不是起草动态测试契约，而是根据
Stage 1 finding、源码和（可选）设备只读事实，提出带证据的入口候选：

    Stage 1 finding -> 入口候选 -> 确定性证据校验 -> 协议描述符匹配

入口候选不是已验证事实。候选必须至少带有源码或设备证据，且入口形态、源码
位置和置信度通过确定性校验；没有足够证据时保留 missing_evidence，不猜端点。
"""

from __future__ import annotations

import json
import re
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .recon_tools import ReconTools
from .recon_loop import _parse_action

_MAX_TURNS_DEFAULT = 12
_MAX_CANDIDATES = 8
_ALLOWED_KINDS = {"hap_udp", "hap_tcp", "unix_dgram", "unix_stream", "event_bus", "cli"}
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
_ENDPOINT_RE = re.compile(r"^(?:[\d.]+|localhost|unknown):\d{1,5}$")
_UNIX_RE = re.compile(r"^/[^\s]+$")
_SOURCE_REF_RE = re.compile(r"^(?P<path>.+?):(?P<start>\d+)(?:-(?P<end>\d+))?$")
_SOURCE_RANGES_RE = re.compile(
    r"^(?P<path>.+?):(?P<ranges>\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)$"
)


ENTRY_DISCOVERY_SYSTEM_PROMPT = (
    "你是 OpenHarmony 动态测试的外部入口发现器。你现在只负责发现并核实"
    "攻击者如何进入目标服务，不负责生成动态测试契约。\n"
    "每轮只输出一个 JSON 动作：\n"
    '{"tool":"read_file","args":{"path":"...","offset":0,"limit":200}}\n'
    '{"tool":"grep","args":{"pattern":"recvfrom|bind|socket","path":"."}}\n'
    '{"tool":"list_dir","args":{"path":"."}}\n'
    '{"tool":"hdc_shell","args":{"argv":["cat","/proc/net/udp"]}}\n'
    '{"tool":"write_note","args":{"text":"..."}}\n'
    '{"tool":"read_notes","args":{}}\n'
    '{"tool":"finalize","args":{"candidates":[...],"missing_evidence":[...]}}\n'
    "工具仅可读取源码和设备事实；不得执行写入、启动、停止、安装、注入或破坏性命令。\n"
    "hdc_shell 的 argv 必须是一个白名单只读命令及其参数；禁止使用 sh/bash -c、分号、管道、\n"
    "重定向或把多个 cat 拼成一条命令。需要同时查看多个文件时，分轮分别调用 cat；工具拒绝后\n"
    "不要重复同一越权组合命令，应改用允许的单条命令。\n"
    "候选格式：\n"
    '{"kind":"hap_udp|hap_tcp|unix_dgram|unix_stream|event_bus|cli",'
    '"endpoint":"127.0.0.1:8283 或 /dev/unix/socket/name 或 domain/id 或命令名",'
    '"confidence":"high|medium|low",'
    '"source_evidence":["path/to/file.cpp:123-130"],'
    '"device_evidence":["设备返回的事实摘要"],'
    '"route_relevance":"direct|possible|unrelated|unknown",'
    '"handler":"接收后实际处理函数", "target_sink":"与当前 finding 对应的 sink",'
    '"dispatch_conditions":["命令/事件/分派条件"],'
    '"state_flow":["状态写入或读取关系"],'
    '"route_evidence":["path/to/file.cpp:200-220"],"reason":"..."}\n'
    "硬规则：\n"
    "1. 不能仅凭 HandleMsg、Process、回调或业务函数名称臆造端口和 socket。\n"
    "2. source_evidence 必须指向仓库内真实源码位置；device_evidence 必须来自设备工具返回。\n"
    "3. 只有发现 bind/listen/accept/recv/recvfrom/read、Unix socket 名称注册、事件订阅或"
    "CLI 注册等证据时，才可以提交候选。中间转发函数不是外部入口。\n"
    "4. 多个可能入口要全部保留，不要为了选一个而删除其他候选。\n"
    "5. 找不到证据时提交空 candidates 和 missing_evidence，不要猜测。\n"
    "6. 如果已有入口线索已经由源码接收函数和设备端点共同支持，不要继续泛搜，"
    "直接 finalize；入口发现不是调用图穷尽分析。\n"
    "7. 如果源码证据同时出现 UDP 与 TCP 入口，必须分别读取 /proc/net/udp 和 "
    "/proc/net/tcp（必要时再查 udp6/tcp6），不能只核实一种传输层后遗漏另一种。\n"
    "8. route_relevance 必须针对当前 finding 的 sink 判断：direct 表示源码已把该入口"
    "连接到目标 sink，possible 表示存在未决分派/状态关系但仍是合理候选，unrelated 表示"
    "同服务但与目标 sink 无关，unknown 表示证据不足。不要把同一服务的全部端点都标成 direct。"
    "9. route_evidence 只能引用当前仓库中真实存在的源码区间；state_flow 只记录状态/"
    "事件关系，不要求在本阶段完成完整参数污点传播（Stage2 负责参数影响验证）。"
    "10. finalize 只提交 JSON，不要附加解释文字。"
)


@dataclass
class EntryCandidate:
    kind: str
    endpoint: str
    confidence: str
    source_evidence: list[str] = field(default_factory=list)
    device_evidence: list[str] = field(default_factory=list)
    route_relevance: str = "unknown"
    handler: str = ""
    target_sink: str = ""
    dispatch_conditions: list[str] = field(default_factory=list)
    state_flow: list[str] = field(default_factory=list)
    route_evidence: list[str] = field(default_factory=list)
    reason: str = ""
    # 当前运行内的候选路由复核证据；不参与 candidate_id 计算，避免同一
    # 入口在复核前后身份漂移。它只记录为何在多候选场景中选择了该入口。
    arbitration_evidence: list[str] = field(default_factory=list)
    arbitration_reason: str = ""

    @property
    def candidate_id(self) -> str:
        material = "|".join([
            self.kind, self.endpoint, self.handler, self.target_sink,
            *self.source_evidence, *self.route_evidence,
        ])
        return "entry-" + hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def hint(self) -> str:
        if self.kind in {"hap_udp", "hap_tcp", "unix_dgram", "unix_stream", "cli"}:
            return f"{self.kind} {self.endpoint}".strip()
        return f"event_bus {self.endpoint or 'unknown/unknown'} 触发"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "endpoint": self.endpoint,
            "hint": self.hint,
            "confidence": self.confidence,
            "source_evidence": list(self.source_evidence),
            "device_evidence": list(self.device_evidence),
            "candidate_id": self.candidate_id,
            "route_relevance": self.route_relevance,
            "handler": self.handler,
            "target_sink": self.target_sink,
            "dispatch_conditions": list(self.dispatch_conditions),
            "state_flow": list(self.state_flow),
            "route_evidence": list(self.route_evidence),
            "reason": self.reason,
            "arbitration_evidence": list(self.arbitration_evidence),
            "arbitration_reason": self.arbitration_reason,
        }


@dataclass
class EntryDiscoveryResult:
    status: str = ""  # finalized / no_candidate / budget_exhausted / llm_unavailable
    candidates: list[EntryCandidate] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    turns_used: int = 0
    device_commands_used: int = 0
    error: str = ""
    audit: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "candidates": [c.to_dict() for c in self.candidates],
            "missing_evidence": list(self.missing_evidence),
            "notes": list(self.notes),
            "turns_used": self.turns_used,
            "device_commands_used": self.device_commands_used,
            "error": self.error,
            "audit": list(self.audit),
        }


def _source_ref_valid(repo_root: Path, reference: str) -> bool:
    match = _SOURCE_REF_RE.match(str(reference).strip())
    if not match:
        return False
    start = int(match.group("start"))
    end = int(match.group("end") or start)
    if start < 1 or end < start:
        return False
    raw_path = Path(match.group("path"))
    path = raw_path if raw_path.is_absolute() else repo_root / raw_path
    if not path.is_file():
        # Stage 1 经常只展示 basename；仅在仓库中唯一时允许补全，避免按 basename
        # 把两个不同服务的同名文件错误关联。
        matches = [p for p in repo_root.rglob(raw_path.name) if p.is_file()]
        if len(matches) != 1:
            return False
        path = matches[0]
    try:
        total = sum(1 for _ in path.open("rb"))
    except OSError:
        return False
    return end <= total


def _normalize_source_refs(values: list[str]) -> list[str]:
    """把模型常见的 ``file.cpp:10-20,30-40`` 展开为两个证据引用。

    提示词要求数组中的每一项是一个源码区间，但模型经常为了压缩输出把同一
    文件的多个区间写在一项中。这里仅规范化行号后缀，不按逗号拆分路径主体，
    避免破坏合法的目录名或宏生成路径。
    """
    normalized: list[str] = []
    for value in values:
        text = str(value).strip()
        match = _SOURCE_RANGES_RE.match(text)
        if match and "," in match.group("ranges"):
            path = match.group("path")
            for span in match.group("ranges").split(","):
                normalized.append(f"{path}:{span}")
        else:
            normalized.append(text)
    return list(dict.fromkeys(x for x in normalized if x))


def _validate_candidate(raw: Any, repo_root: Path) -> tuple[EntryCandidate | None, str]:
    if not isinstance(raw, dict):
        return None, "候选不是对象"
    kind = str(raw.get("kind", "")).strip().lower()
    endpoint = str(raw.get("endpoint", "")).strip()
    confidence = str(raw.get("confidence", "")).strip().lower()
    if kind not in _ALLOWED_KINDS:
        return None, f"入口类型不支持: {kind!r}"
    if confidence not in _CONFIDENCE_RANK:
        return None, f"confidence 非法: {confidence!r}"
    relevance = str(raw.get("route_relevance", "unknown")).strip().lower()
    if relevance not in {"direct", "possible", "unrelated", "unknown"}:
        return None, f"route_relevance 非法: {relevance!r}"
    if kind in {"hap_udp", "hap_tcp"} and not _ENDPOINT_RE.match(endpoint):
        return None, f"{kind} endpoint 非法: {endpoint!r}"
    if kind in {"unix_dgram", "unix_stream"} and not _UNIX_RE.match(endpoint):
        return None, f"{kind} endpoint 必须是绝对路径: {endpoint!r}"
    if kind == "event_bus" and not endpoint:
        endpoint = "unknown/unknown"
    if kind == "cli" and not endpoint:
        return None, "cli endpoint 为空"
    source = raw.get("source_evidence") or []
    device = raw.get("device_evidence") or []
    if not isinstance(source, list) or not all(isinstance(x, str) for x in source):
        return None, "source_evidence 必须是字符串数组"
    if not isinstance(device, list) or not all(isinstance(x, str) for x in device):
        return None, "device_evidence 必须是字符串数组"
    source = _normalize_source_refs([x for x in source if x.strip()])
    device = [x.strip() for x in device if x.strip()]
    if not source and not device:
        return None, "候选缺少 source_evidence 和 device_evidence"
    bad_refs = [x for x in source if not _source_ref_valid(repo_root, x)]
    if bad_refs:
        return None, f"源码证据无法核验: {bad_refs[:3]}"
    route_evidence = _normalize_source_refs([str(x) for x in (raw.get("route_evidence") or [])
                                             if isinstance(x, str) and x.strip()])
    bad_route_refs = [x for x in route_evidence if not _source_ref_valid(repo_root, x)]
    if bad_route_refs:
        return None, f"路由源码证据无法核验: {bad_route_refs[:3]}"
    def _string_list(key: str) -> list[str]:
        value = raw.get(key) or []
        return [str(x)[:500] for x in value if str(x).strip()] if isinstance(value, list) else []
    return EntryCandidate(
        kind=kind,
        endpoint=endpoint,
        confidence=confidence,
        source_evidence=source[:12],
        device_evidence=device[:12],
        route_relevance=relevance,
        handler=str(raw.get("handler", ""))[:300],
        target_sink=str(raw.get("target_sink", ""))[:500],
        dispatch_conditions=_string_list("dispatch_conditions"),
        state_flow=_string_list("state_flow"),
        route_evidence=route_evidence[:12],
        reason=str(raw.get("reason", ""))[:1000],
    ), ""


def _merge_candidates(candidates: list[EntryCandidate]) -> list[EntryCandidate]:
    merged: dict[str, EntryCandidate] = {}
    for candidate in candidates:
        key = candidate.hint.lower()
        old = merged.get(key)
        if old is None or _CONFIDENCE_RANK[candidate.confidence] > _CONFIDENCE_RANK[old.confidence]:
            merged[key] = candidate
        elif old is not None:
            old.source_evidence = list(dict.fromkeys(old.source_evidence + candidate.source_evidence))[:12]
            old.device_evidence = list(dict.fromkeys(old.device_evidence + candidate.device_evidence))[:12]
            if old.route_relevance == "unknown" or (
                candidate.route_relevance == "direct" and old.route_relevance != "direct"
            ):
                old.route_relevance = candidate.route_relevance
            old.route_evidence = list(dict.fromkeys(old.route_evidence + candidate.route_evidence))[:12]
            old.arbitration_evidence = list(
                dict.fromkeys(old.arbitration_evidence + candidate.arbitration_evidence)
            )[:12]
            old.arbitration_reason = old.arbitration_reason or candidate.arbitration_reason
            old.dispatch_conditions = list(dict.fromkeys(old.dispatch_conditions + candidate.dispatch_conditions))[:12]
            old.state_flow = list(dict.fromkeys(old.state_flow + candidate.state_flow))[:12]
            old.handler = old.handler or candidate.handler
            old.target_sink = old.target_sink or candidate.target_sink
    return list(merged.values())[:_MAX_CANDIDATES]


def _stage1_hint_source_refs(finding: Any, repo_root: Path) -> list[str]:
    """把 Stage 1 已有源码位置整理成可复核的证据引用。

    入口 Agent 因模型限流、安全策略或临时网络故障不可用时，不能把“无
    候选”误写成“无入口”。这里仅提升 Stage 1 已明确给出的 endpoint 线索，
    并保留其源码位置；不从仓库名称或协议族名称猜测新的入口。该候选的
    ``route_relevance`` 固定为 ``possible``，仍需后续路由/协议证据确认。
    """
    paths = list(getattr(finding, "source_paths", []) or [])
    ranges = list(getattr(finding, "evidence_lines", []) or [])
    refs: list[str] = []
    for index, raw_path in enumerate(paths):
        path = Path(str(raw_path))
        resolved = path if path.is_absolute() else repo_root / path
        if not resolved.is_file():
            matches = [p for p in repo_root.rglob(path.name) if p.is_file()]
            if len(matches) != 1:
                continue
            path = matches[0].relative_to(repo_root)
            resolved = repo_root / path
        span = ranges[index] if index < len(ranges) else None
        if isinstance(span, (list, tuple)) and span:
            try:
                start = max(1, int(span[0]))
                end = max(start, int(span[1] if len(span) > 1 else span[0]))
            except (TypeError, ValueError):
                start = end = 1
        else:
            start = end = 1
        refs.append(f"{path.as_posix()}:{start}-{end}")
    return list(dict.fromkeys(refs))


def _stage1_hint_fallback(
    finding: Any, repo_root: Path, tools: ReconTools,
) -> tuple[list[EntryCandidate], list[str]]:
    """从显式 Stage 1 endpoint 线索构造保守入口候选。

    这是“模型不可用时的证据保全”，不是协议或 socket 名称硬编码：只有
    finding.entry_hints 中已经出现的 hap/unix endpoint 才会被提升。若设备
    对象可用，还会执行一次只读 ``/proc/net`` 查询并把结果摘要写入设备证据。
    """
    refs = _stage1_hint_source_refs(finding, repo_root)
    if not refs:
        return [], ["Stage1 入口线索存在，但没有可复核源码位置"]
    result: list[EntryCandidate] = []
    missing: list[str] = []
    for hint in list(getattr(finding, "entry_hints", []) or []):
        text = str(hint).strip()
        match = re.match(r"^(hap_udp|hap_tcp|unix_dgram|unix_stream)\s+(.+)$", text, re.IGNORECASE)
        if not match:
            continue
        kind = match.group(1).lower()
        endpoint = match.group(2).strip()
        device_evidence: list[str] = []
        if tools.hdc is not None and kind in {"hap_udp", "hap_tcp"}:
            table = "udp" if kind == "hap_udp" else "tcp"
            probe = tools.call("hdc_shell", {"argv": ["cat", f"/proc/net/{table}"]})
            if probe.get("ok"):
                port_match = re.search(r":(\d+)$", endpoint)
                port = int(port_match.group(1)) if port_match else 0
                needle = f":{port:04X}" if port else endpoint
                if needle.upper() in str(probe.get("output", "")).upper():
                    device_evidence.append(f"/proc/net/{table} 命中 {endpoint}")
                else:
                    missing.append(f"设备未在 /proc/net/{table} 中确认 {endpoint}")
            else:
                missing.append(f"设备只读查询失败：{probe.get('error', 'unknown')}")
        candidate, error = _validate_candidate({
            "kind": kind,
            "endpoint": endpoint,
            "confidence": "medium",
            "source_evidence": refs,
            "device_evidence": device_evidence,
            "route_relevance": "possible",
            "target_sink": str(getattr(finding, "sink", "")),
            "reason": "模型入口发现不可用；仅保留 Stage 1 明确 endpoint 和源码证据，"
                      "未把该线索升级为 direct 路由。",
        }, repo_root)
        if candidate is not None:
            result.append(candidate)
        elif error:
            missing.append(f"Stage1 入口线索校验失败：{error}")
    return _merge_candidates(result), missing


def run_entry_discovery_loop(
    *,
    finding: Any,
    repo_root: Path,
    hdc=None,
    binding_pair=None,
    max_turns: int = _MAX_TURNS_DEFAULT,
    on_event=None,
) -> EntryDiscoveryResult:
    """在协议描述符匹配前发现外部入口。

    binding_pair 可注入脚本化模型用于测试；真实运行时复用 dynamic_test LLM
    provider。没有模型时不会猜测，只返回 llm_unavailable。
    """
    tools = ReconTools(hdc=hdc, repo_root=repo_root)
    result = EntryDiscoveryResult()
    if binding_pair is None:
        try:
            from .recon_loop import _llm_binding  # noqa: PLC0415
            binding_pair = _llm_binding()
        except Exception:  # pragma: no cover - 防止可选 LLM 依赖影响静态路径
            binding_pair = None
    if binding_pair is None:
        result.status = "llm_unavailable"
        result.notes = list(tools.notes)
        result.error = "入口发现 Agent Loop 的 LLM 不可用"
        fallback, missing = _stage1_hint_fallback(finding, repo_root, tools)
        if fallback:
            result.candidates = fallback
            result.status = "stage1_hint_fallback"
            result.notes.append("LLM 不可用：保留 Stage1 显式入口线索，路由等级降为 possible")
        result.missing_evidence.extend(missing)
        result.device_commands_used = tools.device_commands_used
        result.audit = [a.to_dict() for a in tools.audit]
        return result
    binding, simple_text = binding_pair
    finding_dict = (
        finding.to_prompt_dict()
        if hasattr(finding, "to_prompt_dict")
        else finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
    )
    context = [
        "目标 finding（可能包含 Stage 1 原始上下文；只能把它作为检索线索，不能替代源码/设备证据）:",
        json.dumps(finding_dict, ensure_ascii=False, indent=2),
        "仓库根目录:", str(repo_root),
        "已有入口线索（可验证、可补充，不要盲信）:",
        json.dumps(list(getattr(finding, "entry_hints", []) or []), ensure_ascii=False),
        "请从源码和设备事实中寻找外部入口；先查证，再 finalize。",
    ]
    if hdc is not None:
        context.append(
            "设备取证对象可用：在 finalize 之前必须至少执行一次成功或失败的 "
            "hdc_shell/hilog_grep，只读核实设备状态；若命令失败，把失败原因写进 "
            "missing_evidence，不能只查源码就提交无候选结论。"
        )
    transcript: list[str] = []
    action_keys: list[str] = []
    evidence_actions = 0

    def emit(turn: int, kind: str, tool: str = "", args: Any = None,
             out: Any = None, note: str = "") -> None:
        if on_event is None:
            return
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
            record["note"] = note[:300]
        try:
            on_event({"event": "entry_discovery_turn",
                      "detail": f"入口发现第 {turn} 轮：{kind}"
                                + (f" {tool}" if tool else ""),
                      "record": record})
        except Exception:  # noqa: BLE001
            pass

    for turn in range(1, max_turns + 1):
        result.turns_used = turn
        prompt_parts = list(context)
        prompt_parts.extend([
            "已固化 notes:",
            *[f"[{i}] {note}" for i, note in enumerate(tools.notes, 1)],
            "",
            f"入口发现轮次 {turn}/{max_turns}；最近动作和返回:",
            *transcript[-6:],
            "",
            "下一个动作（只输出一个 JSON）:",
        ])
        if turn >= max_turns - 3:
            prompt_parts.extend([
                "\n⚠️ 收敛阶段：剩余轮次很少。若已有源码接收证据和设备端点，"
                "现在必须 finalize；不要再次读取同一文件、重复相同 grep 或扩大到无关目录。",
                "若仍缺关键证据，立即 finalize 空 candidates，并在 missing_evidence 中说明缺口。",
            ])
        try:
            text = simple_text(binding, "\n".join(prompt_parts),
                               system=ENTRY_DISCOVERY_SYSTEM_PROMPT, max_tokens=12000)
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
        if action_keys.count(action_key) >= 1 and tool != "finalize":
            transcript.append(f"[turn {turn}] 重复动作已执行：{tool}；请改查新证据或 finalize")
            emit(turn, "duplicate", tool, args, note="该动作已经执行过，要求模型收敛")
            action_keys.append(action_key)
            continue
        action_keys.append(action_key)
        if tool == "finalize":
            # 入口发现不能在没有任何源码/设备取证的情况下直接给出“无入口”。
            # 这既防止模型把空的 Stage1 hints 当成事实，也避免模型因第一轮
            # 不愿调用工具而静默漏掉未知 socket。write_note/read_notes 不算取证。
            if evidence_actions == 0:
                transcript.append(
                    f"[turn {turn}] finalize 被拒：尚未执行成功的源码/设备取证动作；"
                    "必须先 read_file/grep/list_dir/hdc_shell/hilog_grep，再提交候选或缺口。"
                )
                emit(turn, "gate", tool, args,
                     note="finalize 被拒：需先执行源码或设备取证")
                continue
            if hdc is not None and tools.device_commands_used == 0:
                transcript.append(
                    f"[turn {turn}] finalize 被拒：设备对象可用但尚未尝试设备取证；"
                    "必须先执行 hdc_shell 或 hilog_grep，再提交候选/缺口。"
                )
                emit(turn, "gate", tool, args,
                     note="设备可用时必须先尝试一次只读设备取证")
                continue
            raw_candidates = args.get("candidates") or []
            if not isinstance(raw_candidates, list):
                transcript.append(f"[turn {turn}] candidates 不是数组")
                emit(turn, "invalid", tool, args, note="candidates 必须是数组")
                continue
            accepted: list[EntryCandidate] = []
            errors: list[str] = []
            for raw in raw_candidates:
                candidate, error = _validate_candidate(raw, repo_root)
                if candidate is not None:
                    accepted.append(candidate)
                elif error:
                    errors.append(error)
            accepted = _merge_candidates(accepted)
            if errors:
                transcript.append(f"[turn {turn}] 候选校验失败: {'；'.join(errors[:4])}")
                emit(turn, "candidate_rejected", tool, args, note="；".join(errors[:3]))
                continue
            result.candidates = accepted
            supplied_missing = args.get("missing_evidence") or []
            if isinstance(supplied_missing, list):
                result.missing_evidence = [str(x)[:500] for x in supplied_missing if str(x).strip()]
            result.status = "finalized" if accepted else "no_candidate"
            emit(turn, "finalize", tool, args,
                 note=f"接受 {len(accepted)} 个入口候选")
            break
        out = tools.call(tool, args)
        if tool in {"read_file", "grep", "list_dir", "hdc_shell", "hilog_grep"} and out.get("ok"):
            evidence_actions += 1
        if tool == "write_note" and out.get("ok"):
            emit(turn, "note", tool, args, out, note=str(args.get("text", "")))
        else:
            emit(turn, "tool", tool, args, out)
        transcript.append(f"[turn {turn}] {tool} {json.dumps(args, ensure_ascii=False)[:400]}\n"
                          f"→ {json.dumps(out, ensure_ascii=False)[:3000]}")
    else:
        result.status = "budget_exhausted"
        result.error = f"{max_turns} 轮未 finalize"
    result.notes = list(tools.notes)
    result.device_commands_used = tools.device_commands_used
    # LLM 可能在请求阶段被提供方拒绝或网络中断。此时保留显式 Stage 1
    # endpoint，比返回空候选更安全；后续描述符 Agent 和设备自证仍会继续
    # 验证，不会把该 fallback 当成 direct 入口。
    if not result.candidates and result.status in {"llm_unavailable", "budget_exhausted"}:
        fallback, missing = _stage1_hint_fallback(finding, repo_root, tools)
        if fallback:
            result.candidates = fallback
            result.status = "stage1_hint_fallback"
            result.notes.append("入口 Agent 未完成：保留 Stage1 显式入口线索，路由等级降为 possible")
        result.missing_evidence.extend(missing)
    result.audit = [a.to_dict() for a in tools.audit]
    if not result.status:
        result.status = "budget_exhausted"
        result.error = result.error or f"{max_turns} 轮未完成入口发现"
    return result


__all__ = [
    "ENTRY_DISCOVERY_SYSTEM_PROMPT",
    "EntryCandidate",
    "EntryDiscoveryResult",
    "run_entry_discovery_loop",
]
