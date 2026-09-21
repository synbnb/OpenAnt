"""协议描述符合成器（自动化方案 §6）：库未命中时 LLM 起草 + 源码核对兜底。

流水（§6.1）：
  源码输入 → LLM 起草 ProtocolDescriptor 草案 → 确定性核对（每个字段名
  必须在证据源码中逐一 grep 到，grep 不到整份拒绝）→ 合法请求自证
  （发送一条全默认值合法报文，服务侧日志出现处理路径才算编码正确）→
  默认首次合成 REQUIRES_HUMAN_APPROVAL（兼容旧流程）；动态测试自动路径在
  route_scope、字段证据和编码形态都通过确定性校验后可显式 auto_approve，
  注册为带证据的通用协议描述符，而不是按样本硬编码协议。

人工审查的是"协议族声明"，成本 O(协议族数) 而非 O(样本数)——这是扩展性的来源。
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import FieldSpec, Guard, ProtocolDescriptor, SendTransform
from .agent.recon_tools import ReconTools

# ---------------------------------------------------------------------------
# LLM 基础设施（与 refine_loop / contract_compiler 相同复用路径）
# ---------------------------------------------------------------------------

def _llm_binding():
    try:
        path = Path(__file__).resolve()
        root = next((parent for parent in path.parents if (parent / "libs" / "vulnfounder-core").is_dir()), path.parents[3])
        core = str(root / "libs" / "vulnfounder-core")
        if core not in sys.path:
            sys.path.insert(0, core)
        from utilities.llm.helpers import simple_text  # noqa: PLC0415
        from utilities.llm.registry import (  # noqa: PLC0415
            build_phase_registry,
            load_config_file,
            resolve_llm_config,
        )

        cf = load_config_file()
        lc = resolve_llm_config(cf, None)
        registry = build_phase_registry(cf, lc)
        return registry.get("dynamic_test"), simple_text
    except Exception:  # noqa: BLE001
        return None


_SYNTH_SYSTEM_PROMPT = (
    "你是 OpenHarmony 协议描述符合成器。输入是一个服务端/Stub 的序列化与解析源码。\n"
    "任务：起草 ProtocolDescriptor JSON：\n"
    "{\n"
    '  "descriptor_id": "<协议族名snake_case>",\n'
    '  "endianness": "host" | "ascii" | "little",\n'
    '  "framing": "single_message" | "frame_sequence" | "stream_tlv",\n'
    '  "transports": ["unix_dgram" | "unix_stream" | "udp" | "tcp" ...],\n'
    '  "fields": [{"name": "<源码 struct/常量表中的字段名>", "type": "string|int64|u32|u64|double|bool",\n'
    '              "order": <序号>, "evidence": "<file.cpp:行> 字段来源"}],\n'
    '  "known_guards": [{"name": "<检查名>", "evidence": "<file.cpp:行>",\n'
    '                    "checked_by": "<检查语义>", "guard_log_hints": ["<设备侧日志关键词>"]}],\n'
    '  "on_send_transforms": [],\n'
    '  "structure_evidence": "<整体布局一句话+证据>",\n'
    '  "encoder_kind": "raw_text|key_value|json|custom",\n'
    '  "wire_format": {"pair_separator":"::", "record_separator":"\\n", "terminator":""}\n'
    '  "legal_probe": {"mode":"udp|tcp|local", "host":"...", "port":0,\n'
    '                   "first":"无害合法帧", "second":"", "third":"",\n'
    '                   "evidence":"<file.cpp:行>"}\n'
    "}\n"
    "硬规则：\n"
    "1. fields[].name 必须逐字出现在源码 struct 定义或键常量表中——会被 grep 核对，"
    "编造一个字段整份草案作废。\n"
    "2. 每个 known_guard 必须带源码行证据。\n"
    "3. legal_probe 只能是无害合法请求，不能包含 marker、echo、分号、管道、重定向或其它"
    "shell 控制符；它用于设备侧自证，不是漏洞 payload。\n"
    "4. 如果字段证据不足，先用 read_file/grep 查找解析器、命令表、字段常量和分帧逻辑，"
    "不要猜字段名；finalize 被字段校验拒绝后，根据反馈补证并重新提交。\n"
    "4a. 只描述当前 route 需要的协议事实：route_context 中的 handler、dispatch_conditions、"
    "target_sink 和 state_flow 是范围边界。raw_text/单帧或帧序列协议通常不需要声明业务字段，"
    "此时 fields 可以为空；不要把同一目录里其它命令、设备信息查询、日志字段或无关结构体"
    "抄进 fields。只有字段确实参与当前 route 的分帧、解析、守卫或触发条件时才声明，并给出"
    "当前源码证据。若当前证据不足以确定字段，不要用无关字段凑数量，继续查证或返回"
    "insufficient。\n"
    "4b. 当前 route 的源码文件可以用绝对路径或仓库相对路径表示；证据必须是当前 bundle"
    "中的真实 file:line，不能只写‘文件名 + 函数名’或从同目录其它实现推断。\n"
    "4c. 协议守卫经常跨文件生效：不要只看 recv/dispatch 函数里的通用 token 检查。"
    "在 finalize 前，必须检查当前 route 对应的默认开关、构造函数、启动参数、配置/属性"
    "以及 Set*Token/SetNeed*Token 一类 setter 的调用位置。可以在当前 route 源码目录及其"
    "直接依赖中 grep 守卫字段或 setter，再 read_file 读取命中实现；这些动作不是针对某个"
    "服务的硬编码，而是为了确认同一 endpoint 在当前启动模式下是否真的要求 token。若源码"
    "明确表明某种合法启动方式关闭了守卫，应把该证据写入 known_guards 和 legal_probe；"
    "不要仅因存在通用 token 分支就宣称协议不可生成。反之，若选定 route 无条件要求一个"
    "设备侧无法取得的 token，才应返回 insufficient。\n"
    "4d. 如果源码出现 SplitMsg、StrSplit 或按字符串分隔符拆包，不能用空 fields 的"
    "raw_text 草案逃避协议恢复；必须继续查找当前 route 的命令/消息表和分隔符证据。\n"
    "5. 只输出一个 JSON 动作对象。"
)


@dataclass
class SynthesisResult:
    """合成结果：approved 前永远停在 REQUIRES_HUMAN_APPROVAL。"""

    descriptor: ProtocolDescriptor | None
    status: str                        # REQUIRES_HUMAN_APPROVAL / REJECTED_FIELD_CHECK / REQUIRES_PROTOCOL_REVIEW / APPROVED
    field_check: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    llm_used: bool = False
    attempts: int = 0
    evidence_paths: list[str] = field(default_factory=list)
    feedback_history: list[str] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "field_check": dict(self.field_check),
            "errors": list(self.errors),
            "llm_used": self.llm_used,
            "attempts": self.attempts,
            "evidence_paths": list(self.evidence_paths),
            "feedback_history": list(self.feedback_history),
            "audit": list(self.audit),
            "descriptor": self.descriptor.to_dict() if self.descriptor else None,
        }


# ---------------------------------------------------------------------------
# 确定性核对：字段名逐一在源码证据中出现
# ---------------------------------------------------------------------------

def _read_source(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# 允许 ``file.cpp:10-20`` 后面跟一段人类可读说明。模型通常会把证据写成
# ``file.cpp:10-20 解析字段``；如果只匹配到行号但把尾注也当成路径，补证工具
# 会误报“文件不可读”，随后无意义地重试。
_SOURCE_REF_RE = re.compile(r"^\s*(.+?):(\d+)(?:-(\d+))?(?:\s|;|；|,|、|$)")


def _normalize_source_ref(ref: str) -> str:
    """把 file:line 或 file:start-end 还原为可读取的文件路径。"""
    text = str(ref or "").strip()
    match = _SOURCE_REF_RE.match(text)
    return match.group(1) if match else text


def _unique_source_paths(paths: list[str]) -> list[str]:
    result: list[str] = []
    for value in paths:
        normalized = _normalize_source_ref(value)
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def _resolve_source_ref(ref: str, repo_root: str = "") -> tuple[str, Path] | None:
    """将 file:line[ 尾注] 解析成展示名和实际文件路径。"""
    text = str(ref or "").strip()
    normalized = _normalize_source_ref(text)
    if not normalized:
        return None
    raw = Path(normalized)
    root = Path(repo_root) if repo_root else None
    path = raw if raw.is_absolute() else (root / raw if root else raw)
    return normalized, path


def _resolve_source_ref_from_bundle(
    ref: str, source_paths: list[str], repo_root: str = "",
) -> tuple[str, Path] | None:
    """在当前源码证据 bundle 内解析简写文件名。

    LLM 常把已经展示过的 ``path/to/file.cpp`` 简写成 ``file.cpp:line``。
    只有当当前 bundle 中恰好存在一个同名文件时才接受该简写；不做全仓
    模糊匹配，避免把另一个组件的同名文件错误地当作证据。
    """
    resolved = _resolve_source_ref(ref, repo_root)
    if resolved is not None and resolved[1].is_file():
        return resolved
    normalized = _normalize_source_ref(ref)
    name = Path(normalized).name
    if not name:
        return None
    candidates: list[tuple[str, Path]] = []
    for raw in source_paths:
        display = _normalize_source_ref(str(raw))
        path = Path(display) if Path(display).is_absolute() else (Path(repo_root) / display if repo_root else Path(display))
        if path.is_file() and path.name == name:
            candidates.append((display, path))
    if len(candidates) == 1:
        return candidates[0]
    return None


def verify_fields_against_source(
    descriptor: ProtocolDescriptor,
    source_paths: list[str],
    *,
    repo_root: str = "",
) -> dict[str, Any]:
    """每个 fields[].name 必须在至少一份源码文件中出现（逐字 grep）。

    返回 {"verified": [...], "missing": [...], "sources_read": [...]}。
    """
    sources: list[str] = []
    source_names: list[str] = []
    repo = Path(repo_root) if repo_root else None
    all_paths = _unique_source_paths(list(source_paths) + [f.evidence for f in descriptor.fields])
    for src in all_paths:
        resolved = _resolve_source_ref_from_bundle(src, source_paths, repo_root)
        path = resolved[1] if resolved is not None else (
            Path(src) if Path(src).is_absolute() else (repo / src if repo else Path(src))
        )
        text = _read_source(path)
        if text:
            sources.append(text)
            source_names.append(src)
    verified: list[str] = []
    missing: list[str] = []
    verified_by: dict[str, list[str]] = {}
    for f in descriptor.fields:
        if not f.name:
            missing.append(f.name)
            continue
        hits = [name for name, text in zip(source_names, sources) if f.name in text]
        if hits:
            verified.append(f.name)
            verified_by[f.name] = hits
        else:
            missing.append(f.name)
    return {
        "verified": verified,
        "missing": missing,
        "sources_read": source_names,
        "verified_by": verified_by,
    }


def verify_descriptor_evidence(
    descriptor: ProtocolDescriptor,
    source_paths: list[str],
    *,
    repo_root: str = "",
) -> dict[str, Any]:
    """核验描述符每个声明的证据文件确实可读且包含对应事实。

    ``verify_fields_against_source`` 是兼容旧描述符的宽松字段存在性检查；
    Agent Loop 使用本函数的严格视图：字段、守卫、发送变换和合法探测都必须
    指向当前仓库内可读取的源码证据。它只验证“证据片段存在”，不把文本出现
    自动升级成语义绑定，语义仍由模型和后续设备自证负责。
    """
    check = verify_fields_against_source(descriptor, source_paths, repo_root=repo_root)
    failures: list[str] = []
    verified_declarations: list[str] = []

    def check_decl(kind: str, name: str, evidence: str, needle: str | None = None) -> None:
        if not str(evidence or "").strip():
            failures.append(f"{kind}.{name} 缺少源码 evidence")
            return
        resolved = _resolve_source_ref_from_bundle(evidence, source_paths, repo_root)
        if resolved is None:
            failures.append(f"{kind}.{name} evidence 不是 file:line 引用：{evidence}")
            return
        display, path = resolved
        text = _read_source(path)
        if not text:
            failures.append(f"{kind}.{name} evidence 文件不可读：{display}")
            return
        if needle and needle not in text:
            failures.append(f"{kind}.{name} evidence 文件未出现声明名：{display}")
            return
        verified_declarations.append(f"{kind}.{name}")

    for item in descriptor.fields:
        check_decl("field", item.name, item.evidence, item.name)
    for item in descriptor.known_guards:
        check_decl("guard", item.name, item.evidence)
    for item in descriptor.on_send_transforms:
        check_decl("transform", item.name, item.evidence)
    # 合法探测也必须能回溯到解析/分派源码；否则设备发送成功只能证明某个
    # 端口可写，不能证明它是当前 finding 的合法协议帧。
    probe = descriptor.legal_probe or {}
    check_decl("legal_probe", "evidence", str(probe.get("evidence", "")))
    return {
        **check,
        "evidence_failures": failures,
        "verified_declarations": verified_declarations,
    }


# ---------------------------------------------------------------------------
# LLM 起草
# ---------------------------------------------------------------------------

def _llm_descriptor_draft(
    source_texts: list[str], *, source_names: list[str], route_context: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    pair = _llm_binding()
    if pair is None:
        return None
    binding, simple_text = pair
    parts = ["待分析的协议源码（序号与文件名对应）:"]
    for name, text in zip(source_names, source_texts):
        parts.append(f"===== {name} =====")
        # 上限 60KB 防上下文爆炸
        parts.append(text[:60000])
    if route_context:
        parts.append("===== 当前 finding 的路由切片（只描述本次目标，不要混入同服务其它端点） =====")
        parts.append(json.dumps(route_context, ensure_ascii=False, indent=2))
    text = simple_text(binding, "\n".join(parts), system=_SYNTH_SYSTEM_PROMPT, max_tokens=8000)
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    try:
        raw = json.loads(text.strip())
    except json.JSONDecodeError:
        return None
    return raw if isinstance(raw, dict) else None


def _descriptor_from_draft(raw: dict[str, Any]) -> ProtocolDescriptor | None:
    try:
        fields = [
            FieldSpec(
                name=str(f["name"]),
                type=str(f.get("type", "string")),
                order=int(f.get("order", 0)),
                evidence=str(f.get("evidence", "")),
                case_sensitive=bool(f.get("case_sensitive", False)),
                required=bool(f.get("required", False)),
            )
            for f in raw.get("fields", [])
        ]
        guards = [
            Guard(
                name=str(g["name"]),
                evidence=str(g.get("evidence", "")),
                checked_by=str(g.get("checked_by", "")),
                guard_log_hints=[str(h) for h in g.get("guard_log_hints", [])],
            )
            for g in raw.get("known_guards", [])
        ]
        transforms = [
            SendTransform(name=str(t["name"]), kind=str(t.get("kind", "")), evidence=str(t.get("evidence", "")))
            for t in raw.get("on_send_transforms", [])
        ]
        return ProtocolDescriptor(
            descriptor_id=str(raw["descriptor_id"]),
            endianness=str(raw.get("endianness", "host")),
            framing=str(raw.get("framing", "single_message")),
            transports=[str(t) for t in raw.get("transports", [])],
            fields=fields,
            known_guards=guards,
            on_send_transforms=transforms,
            structure_evidence=str(raw.get("structure_evidence", "")),
            encoder_kind=str(raw.get("encoder_kind", "custom")),
            wire_format=dict(raw.get("wire_format") or {}),
            legal_probe=dict(raw.get("legal_probe") or {}),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _parse_action(text: str) -> dict[str, Any] | None:
    """解析描述符 Agent 的单个 JSON 动作。"""
    body = str(text or "").strip()
    if body.startswith("```"):
        body = body.split("```", 2)[1]
        if body.lstrip().startswith("json"):
            body = body.lstrip()[4:]
    try:
        value = json.loads(body.strip())
    except json.JSONDecodeError:
        # 模型偶尔在 JSON 前后带解释文字；只取首个平衡对象。
        start = body.find("{")
        end = body.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            value = json.loads(body[start:end + 1])
        except json.JSONDecodeError:
            return None
    if not isinstance(value, dict) or not isinstance(value.get("tool"), str):
        return None
    args = value.get("args")
    return {"tool": value["tool"], "args": args if isinstance(args, dict) else {}}


def _source_bundle(paths: list[str], repo_root: str, *, max_bytes: int = 90000) -> str:
    """读取当前证据文件集合，保留文件边界并限制上下文大小。"""
    repo = Path(repo_root) if repo_root else None
    chunks: list[str] = []
    total = 0
    for raw in _unique_source_paths(paths):
        path = Path(raw) if Path(raw).is_absolute() else (repo / raw if repo else Path(raw))
        text = _read_source(path)
        if not text:
            continue
        piece = f"===== {raw} =====\n{text}"
        remaining = max_bytes - total
        if remaining <= 0:
            break
        chunks.append(piece[:remaining])
        total += min(len(piece), remaining)
    return "\n".join(chunks)


def _validate_legal_probe(probe: dict[str, Any]) -> list[str]:
    """校验设备自证报文不是漏洞变异载荷。"""
    if not probe:
        return ["缺少 legal_probe：自动描述符必须提供一条无害合法请求"]
    errors: list[str] = []
    for key in ("first", "second", "third", "payload"):
        value = probe.get(key)
        if value is None or value == "":
            continue
        text = str(value)
        if "__" in text or re.search(r"[;|&>$`\n\r]", text):
            errors.append(f"legal_probe.{key} 含攻击/模板控制字符，必须是无害合法报文")
        if re.search(r"\b(echo|popen|system|exec)\b", text, re.IGNORECASE):
            errors.append(f"legal_probe.{key} 含命令执行词，禁止用于合法自证")
    mode = str(probe.get("mode", ""))
    if mode not in {"udp", "tcp", "local"}:
        errors.append("legal_probe.mode 必须是 udp、tcp 或 local")
    if mode in {"udp", "tcp"}:
        try:
            port = int(probe.get("port", 0))
        except (TypeError, ValueError):
            port = 0
        if not (1 <= port <= 65535):
            errors.append("legal_probe.port 不在合法端口范围")
        if not str(probe.get("host", "")):
            errors.append("legal_probe.host 不能为空")
    if not any(probe.get(key) for key in ("first", "second", "third", "payload")):
        errors.append("legal_probe 至少需要一条 first/second/third/payload")
    return errors


def _validate_wire_format_against_source(
    descriptor: ProtocolDescriptor, source_paths: list[str], *, repo_root: str = "",
) -> list[str]:
    """核对文本 key/value 描述符声明的分隔符是否有当前源码依据。

    ``encoder_kind=key_value`` 的 ``pair_separator`` 会直接决定运行器发出的
    线路帧。仅做字段名存在性检查不足以发现模型把逻辑运算符（例如 ``||``）
    误当成协议分隔符。这里要求分隔符至少作为字符串/字符字面量出现在本轮
    源码证据中；不推断具体服务，也不限制二进制/custom 描述符。
    """
    if descriptor.encoder_kind != "key_value":
        return []
    wire = descriptor.wire_format or {}
    separator = str(wire.get("pair_separator") or "")
    if not separator:
        return ["key_value 描述符缺少 wire_format.pair_separator"]
    texts: list[str] = []
    for raw in _unique_source_paths(source_paths):
        resolved = _resolve_source_ref(raw, repo_root)
        if resolved is None:
            continue
        _, path = resolved
        text = _read_source(path)
        if text:
            texts.append(text)
    # 只接受带引号的源码字面量，避免把 C/C++ 逻辑表达式中的 ||、&& 等
    # 偶然命中；转义形式保留原文检查，能覆盖常见的 "\\n"/"\\t"。
    literal_values: list[str] = []
    literal_re = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
    for text in texts:
        for literal in literal_re.findall(text):
            literal_values.append(literal[1:-1])
    # 单字符分隔符经常以字符常量或解析表达式中的单字符比较出现；在源码
    # 中出现即可作为弱证据，后续 legal_probe/设备自证仍会继续约束它。多字符
    # 分隔符则必须出现在字符串/字符字面量中，避免把 ``||``/``&&`` 逻辑
    # 运算符误认成线路分隔符。
    if not any(separator in value for value in literal_values):
        if len(separator) == 1 and any(separator in text for text in texts):
            return []
        return [
            f"key_value 的 pair_separator={separator!r} 未在当前源码字符串/字符字面量中找到；"
            "请读取分帧/字段解析实现后提交有源码依据的分隔符"
        ]
    return []


def _validate_protocol_shape_against_source(
    descriptor: ProtocolDescriptor, source_paths: list[str], *, repo_root: str = "",
) -> list[str]:
    """防止把有明确键值分帧证据的协议过早降级成空字段 raw_text。

    这不是服务名称或命令名称规则，而是对当前源码证据的形态校验：如果源码
    明确存在 ``SplitMsg``/``find("::")``/按 ``::`` 拆分等键值分帧操作，描述符
    至少应列出当前 route 的一个字段并声明分隔符。否则模型可能在尚未读取命令
    表时提交一个“看似通用”的 raw_text 草案，随后动态运行器无法构造真实帧。
    二进制/custom 协议不受此检查影响。
    """
    if descriptor.encoder_kind != "raw_text" or descriptor.fields:
        return []
    texts: list[str] = []
    for raw in _unique_source_paths(source_paths):
        resolved = _resolve_source_ref(raw, repo_root)
        if resolved is None:
            continue
        _, path = resolved
        text = _read_source(path)
        if text:
            texts.append(text)
    key_value_patterns = (
        r"\bSplitMsg\s*\(",
        r"\bStrSplit\s*\([^\n;]*(?:\"|')::",
        r"\.find\s*\(\s*(?:\"|')::",
        r"\.substr\s*\([^\n;]*find\s*\(\s*(?:\"|')::",
    )
    if any(re.search(pattern, text) for text in texts for pattern in key_value_patterns):
        return [
            "当前源码包含键值分帧证据，但 descriptor.encoder_kind=raw_text 且 fields 为空；"
            "请读取命令/消息表，声明当前 route 实际使用的字段，并提供 pair_separator 的源码证据"
        ]
    return []


def _descriptor_agent_loop(
    source_paths: list[str], *, repo_root: str, route_context: dict[str, Any] | None,
    binding_pair=None, hdc=None, max_turns: int = 8,
    descriptor_id_override: str = "", on_event=None,
) -> tuple[ProtocolDescriptor | None, list[str], list[str], list[dict[str, Any]], list[str], int]:
    """协议证据补全 Agent：工具查证 → 草案 → 校验反馈 → 重写。"""
    pair = binding_pair or _llm_binding()
    paths = _unique_source_paths(source_paths)
    feedback: list[str] = []
    audit: list[dict[str, Any]] = []
    if pair is None:
        return None, paths, ["LLM 不可用"], audit, feedback, 0
    binding, simple_text = pair
    tools = ReconTools(hdc=hdc, repo_root=Path(repo_root), max_device_commands=12)
    transcript: list[str] = []
    attempts = 0

    def route_path_allowed(raw: str) -> bool:
        """只允许当前 route 的源码文件和其可验证头文件进入证据 bundle。"""
        normalized = _normalize_source_ref(raw)
        if not normalized:
            return False
        # 模型可能把同一文件写成绝对路径，而初始 bundle 使用仓库相对路径；
        # 先规范化到 repo_root 下的相对 POSIX 路径再比较，避免把已给出的入口
        # 文件误判为越界。不能解析到当前仓库的绝对路径仍拒绝。
        normalized_path = Path(normalized)
        canonical = normalized
        if normalized_path.is_absolute():
            try:
                canonical = normalized_path.resolve().relative_to(Path(repo_root).resolve()).as_posix()
            except ValueError:
                return False
        if canonical in paths or normalized in paths:
            return True
        suffix = Path(normalized).suffix.lower()
        # 头文件可能承载消息常量/结构声明，是当前 route 的直接依赖；源码
        # 实现文件可以从当前 route 的有限源码邻域补入：启动构造、默认配置和
        # setter 往往与接收循环位于同一个 client/server 目录，但不一定出现在
        # finding 的候选攻击链中。只允许同目录或直接父目录中的实现文件，避免
        # grep 全仓时把其它组件的同名处理器带进当前协议证据 bundle。
        if suffix in {".h", ".hh", ".hpp", ".hxx", ".inc"}:
            return True
        if suffix not in {".c", ".cc", ".cpp", ".cxx"}:
            return False
        candidate_parent = Path(canonical).parent
        route_parents = {Path(_normalize_source_ref(p)).parent for p in paths}
        for parent in route_parents:
            if candidate_parent == parent or candidate_parent == parent.parent:
                return True
        return False

    for turn in range(1, max_turns + 1):
        def emit(kind: str, detail: str, **extra: Any) -> None:
            """把描述符补证轮次交给统一进度流；展示失败也不能影响闭环。"""
            if on_event is None:
                return
            record: dict[str, Any] = {"turn": turn, "max_turns": max_turns, "kind": kind}
            record.update({k: v for k, v in extra.items() if v is not None})
            try:
                on_event({"event": "descriptor_synthesis_turn", "detail": detail,
                          "record": record})
            except Exception:  # noqa: BLE001 — 进度展示绝不影响协议判定
                pass

        emit("start", f"协议描述符补证第 {turn} 轮开始")
        prompt = (
            "当前 finding 的协议证据补全任务。只围绕当前 route，不要混入同服务其它 endpoint。\n"
            f"route_context:\n{json.dumps(route_context or {}, ensure_ascii=False, indent=2)}\n"
            f"当前源码证据文件:\n{_source_bundle(paths, repo_root)}\n"
            f"已经执行的动作:\n{chr(10).join(transcript[-6:])}\n"
            f"上轮失败反馈:\n{chr(10).join(feedback[-4:]) or '(无)'}\n"
            "可用工具：read_file、grep、list_dir、hdc_shell（只读）或 finalize。"
            "优先补读消息表、分帧/拆包函数、字段常量、守卫和命令分派；对守卫还要"
            "检索默认值、构造函数、启动参数、配置/属性和 Set*Token/SetNeed*Token"
            "调用，确认当前启动模式是否实际启用鉴权。grep 可以在当前 route 的源码"
            "邻域内查找跨文件证据，命中后必须 read_file 核对上下文。"
            "finalize 格式：{\"tool\":\"finalize\",\"args\":{\"descriptor\":{...}}}。"
            "只提交一个 JSON 动作。"
        )
        try:
            text = simple_text(binding, prompt, system=_SYNTH_SYSTEM_PROMPT, max_tokens=10000)
        except Exception as exc:  # noqa: BLE001 — 反馈到调用方，不伪造协议
            message = f"第 {turn} 轮 LLM 异常：{type(exc).__name__}: {str(exc)[:180]}"
            feedback.append(message)
            audit.append({"turn": turn, "kind": "llm_error", "error": message})
            emit("llm_error", message, error=message[:240])
            continue
        action = _parse_action(text)
        if action is None:
            message = f"第 {turn} 轮输出不是合法 JSON 动作，请只输出一个 JSON 对象"
            feedback.append(message)
            audit.append({"turn": turn, "kind": "invalid", "error": message})
            emit("invalid", message)
            continue
        tool = action["tool"]
        args = action["args"]
        action_summary = {k: (str(v)[:180] if not isinstance(v, (int, float, bool)) else v)
                          for k, v in list(args.items())[:6]}
        emit("action", f"协议描述符补证第 {turn} 轮：{tool}", tool=tool, args=action_summary)
        if tool == "finalize":
            raw = args.get("descriptor") or args.get("draft")
            if not isinstance(raw, dict):
                message = "finalize 缺少 descriptor JSON 对象"
                feedback.append(message)
                audit.append({"turn": turn, "tool": "finalize", "status": "REJECTED", "error": message})
                emit("feedback", message, tool="finalize", status="REJECTED")
                continue
            descriptor = _descriptor_from_draft(raw)
            attempts += 1
            if descriptor is None:
                message = "descriptor 结构不合法，必须包含 descriptor_id、fields、encoder_kind、wire_format、legal_probe"
                feedback.append(message)
                audit.append({"turn": turn, "tool": "finalize", "status": "REJECTED", "error": message})
                emit("feedback", message, tool="finalize", status="REJECTED")
                continue
            if descriptor_id_override:
                descriptor.descriptor_id = descriptor_id_override
            if descriptor.encoder_kind not in {"raw_text", "key_value", "json", "custom"}:
                message = f"encoder_kind 不支持：{descriptor.encoder_kind}"
                feedback.append(message)
                audit.append({"turn": turn, "tool": "finalize", "status": "REJECTED", "error": message})
                emit("feedback", message, tool="finalize", status="REJECTED")
                continue
            check = verify_descriptor_evidence(descriptor, paths, repo_root=repo_root)
            probe_errors = _validate_legal_probe(descriptor.legal_probe)
            if check["missing"] or check.get("evidence_failures"):
                missing = list(check["missing"])
                evidence_failures = list(check.get("evidence_failures", []))
                message = (
                    "协议源码证据不足：缺少字段 " + (", ".join(missing) or "(无)") +
                    ("；" + "; ".join(evidence_failures[:6]) if evidence_failures else "") +
                    "；请 grep 字段名/命令表并 read_file 读取命中文件，再重新 finalize。"
                    f" 当前可读文件：{check['sources_read']}"
                )
                feedback.append(message)
                audit.append({"turn": turn, "tool": "finalize", "status": "REJECTED",
                    "error": message, "field_check": check})
                emit("feedback", message, tool="finalize", status="REJECTED",
                     missing_fields=missing, evidence_failures=evidence_failures[:6])
                continue
            if probe_errors:
                feedback.extend(probe_errors)
                audit.append({"turn": turn, "tool": "finalize", "status": "REJECTED",
                              "error": list(probe_errors), "field_check": check})
                emit("feedback", "合法探测报文校验失败：" + "; ".join(probe_errors),
                     tool="finalize", status="REJECTED")
                continue
            wire_errors = _validate_wire_format_against_source(descriptor, paths, repo_root=repo_root)
            if wire_errors:
                feedback.extend(wire_errors)
                audit.append({"turn": turn, "tool": "finalize", "status": "REJECTED",
                              "error": list(wire_errors), "field_check": check})
                emit("feedback", "线路编码证据校验失败：" + "; ".join(wire_errors),
                     tool="finalize", status="REJECTED")
                continue
            shape_errors = _validate_protocol_shape_against_source(
                descriptor, paths, repo_root=repo_root,
            )
            if shape_errors:
                feedback.extend(shape_errors)
                audit.append({"turn": turn, "tool": "finalize", "status": "REJECTED",
                              "error": list(shape_errors), "field_check": check})
                emit("feedback", "协议形态与源码不一致：" + "; ".join(shape_errors),
                     tool="finalize", status="REJECTED")
                continue
            feedback.append("字段、编码形态和合法探测报文校验通过")
            approved = {"turn": turn, "tool": "finalize", "status": "APPROVED",
                        "verified_fields": check["verified"], "verified_by": check["verified_by"]}
            audit.append(approved)
            emit("approved", f"协议描述符补证第 {turn} 轮通过字段与合法报文校验",
                 tool="finalize", status="APPROVED", verified_fields=list(check["verified"]))
            return descriptor, paths, feedback, audit, feedback, attempts
        # 读取带行号的源码引用时，工具需要纯文件路径。
        if tool == "read_file" and isinstance(args.get("path"), str):
            args = dict(args)
            args["path"] = _normalize_source_ref(args["path"])
            if not route_path_allowed(args["path"]):
                message = (
                    f"路径不属于当前 route 证据范围：{args['path']}；请只读取当前入口/候选链文件，"
                    "或读取其头文件依赖"
                )
                out = {"ok": False, "error": message}
                audit.append({"turn": turn, "tool": tool, "args": args, "result": out})
                feedback.append(message)
                transcript.append(f"[turn {turn}] {tool} {json.dumps(args, ensure_ascii=False)}\n→ {json.dumps(out, ensure_ascii=False)}")
                emit("feedback", message, tool=tool, status="REJECTED")
                continue
            if args["path"] not in paths:
                paths.append(args["path"])
        out = tools.call(tool, args)
        # grep 可以在目录上执行，但返回结果只保留当前 route 文件和头文件；
        # 这比把整棵组件目录加入描述符证据更保守，也不依赖具体服务名称。
        if out.get("ok") and tool == "grep":
            filtered: list[str] = []
            for line in str(out.get("output", "")).splitlines():
                match = re.match(r"^(.+?):\d+(?::|$)", line.strip())
                if match and route_path_allowed(match.group(1)):
                    filtered.append(line)
            out["output"] = "\n".join(filtered) or "(当前 route 范围内无命中)"
        audit.append({"turn": turn, "tool": tool, "args": args, "result": out})
        if out.get("ok") and tool == "grep":
            # grep 返回的 file:line 也是可继续读取的源码证据；仅收录仓库内
            # 实际存在的文件，避免把模型输出中的路径当成事实。
            for line in str(out.get("output", "")).splitlines():
                match = re.match(r"^(.+?):\d+(?::|$)", line.strip())
                if not match:
                    continue
                candidate_path = _normalize_source_ref(match.group(1))
                root = Path(repo_root) if repo_root else Path(".")
                resolved = Path(candidate_path)
                if not resolved.is_absolute():
                    resolved = root / resolved
                if resolved.is_file() and candidate_path not in paths:
                    paths.append(candidate_path)
        transcript.append(f"[turn {turn}] {tool} {json.dumps(args, ensure_ascii=False)}\n→ {json.dumps(out, ensure_ascii=False)[:2500]}")
        if not out.get("ok"):
            message = f"工具 {tool} 失败：{out.get('error', 'unknown')}"
            feedback.append(message)
            emit("feedback", message, tool=tool, status="REJECTED")
        else:
            emit("tool_result", f"协议描述符补证第 {turn} 轮：{tool} 已返回证据",
                 tool=tool, status="OK", output=str(out.get("output", ""))[:240])
    return None, paths, feedback or [f"{max_turns} 轮未得到通过校验的描述符"], audit, feedback, attempts


# ---------------------------------------------------------------------------
# 合成主流程
# ---------------------------------------------------------------------------

def synthesize_descriptor(
    source_paths: list[str],
    *,
    repo_root: str = "",
    draft_override: dict[str, Any] | None = None,
    route_context: dict[str, Any] | None = None,
    descriptor_id_override: str = "",
    auto_approve: bool = False,
    binding_pair=None,
    hdc=None,
    max_turns: int = 8,
    on_event=None,
) -> SynthesisResult:
    """源码 → ProtocolDescriptor 草案 → 字段核对 → 人工闸门。

    draft_override 用于测试注入（跳过 LLM）。
    """
    repo = Path(repo_root) if repo_root else None
    # 证据引用通常带 ``file.cpp:line`` 或 ``file.cpp:start-end``。先归一化
    # 再读取初始上下文，否则带行号的路径会被当成文件名而读空，Agent 首轮
    # 看不到已经提供的源码，容易出现无谓的“字段证据不足”重试。
    evidence_paths = _unique_source_paths(source_paths)
    texts: list[str] = []
    for src in evidence_paths:
        path = Path(src) if Path(src).is_absolute() else (repo / src if repo else Path(src))
        texts.append(_read_source(path))
    if not any(texts):
        return SynthesisResult(
            descriptor=None, status="REQUIRES_PROTOCOL_REVIEW",
            errors=["全部源码文件不可读，无法合成"],
        )

    attempts = 0
    feedback_history: list[str] = []
    audit: list[dict[str, Any]] = []
    if draft_override is not None:
        raw = draft_override
    else:
        descriptor, evidence_paths, loop_errors, audit, feedback_history, attempts = _descriptor_agent_loop(
            evidence_paths, repo_root=repo_root, route_context=route_context,
            binding_pair=binding_pair, hdc=hdc, max_turns=max_turns,
            descriptor_id_override=descriptor_id_override,
            on_event=on_event,
        )
        if descriptor is not None:
            if not auto_approve or not route_context:
                return SynthesisResult(
                    descriptor=descriptor, status="REQUIRES_HUMAN_APPROVAL",
                    field_check=verify_descriptor_evidence(descriptor, evidence_paths, repo_root=repo_root),
                    llm_used=True, attempts=attempts, evidence_paths=evidence_paths,
                    feedback_history=feedback_history, audit=audit,
                )
            return SynthesisResult(
                descriptor=descriptor, status="APPROVED",
                field_check=verify_descriptor_evidence(descriptor, evidence_paths, repo_root=repo_root),
                llm_used=True, attempts=attempts, evidence_paths=evidence_paths,
                feedback_history=feedback_history, audit=audit,
            )
        return SynthesisResult(
            descriptor=None, status="REJECTED_FIELD_CHECK" if attempts else "REQUIRES_PROTOCOL_REVIEW",
            errors=loop_errors, llm_used=True, attempts=attempts,
            evidence_paths=evidence_paths, feedback_history=feedback_history, audit=audit,
        )
    if raw is None:
        return SynthesisResult(
            descriptor=None, status="REQUIRES_PROTOCOL_REVIEW",
            errors=["LLM 不可用或输出不合法"], llm_used=False,
        )

    descriptor = _descriptor_from_draft(raw)
    if descriptor is None:
        return SynthesisResult(
            descriptor=None, status="REQUIRES_PROTOCOL_REVIEW",
            errors=["草案缺必填键（descriptor_id/fields）或类型不符"],
            llm_used=False, attempts=1, evidence_paths=evidence_paths,
        )

    if descriptor_id_override:
        descriptor.descriptor_id = descriptor_id_override
    if descriptor.encoder_kind not in {"raw_text", "key_value", "json", "custom"}:
        return SynthesisResult(
            descriptor=descriptor, status="REQUIRES_PROTOCOL_REVIEW",
            errors=[f"不支持的 encoder_kind: {descriptor.encoder_kind}"],
            llm_used=False, attempts=1, evidence_paths=evidence_paths,
        )

    # 确定性核对：字段名逐一 grep（方案 §6.1 第 2 步）
    check = verify_fields_against_source(descriptor, evidence_paths, repo_root=repo_root)
    if check["missing"] or not check["verified"]:
        return SynthesisResult(
            descriptor=descriptor, status="REJECTED_FIELD_CHECK",
            field_check=check,
            errors=[f"字段核对失败（疑似幻觉字段）: {check['missing']}"],
            llm_used=False, attempts=1, evidence_paths=evidence_paths,
        )

    probe_errors = _validate_legal_probe(descriptor.legal_probe)
    if auto_approve and probe_errors:
        return SynthesisResult(
            descriptor=descriptor, status="REJECTED_FIELD_CHECK",
            field_check=check, errors=probe_errors, llm_used=False, attempts=1,
            evidence_paths=evidence_paths,
        )

    shape_errors = _validate_protocol_shape_against_source(
        descriptor, evidence_paths, repo_root=repo_root,
    )
    if auto_approve and shape_errors:
        return SynthesisResult(
            descriptor=descriptor, status="REJECTED_FIELD_CHECK",
            field_check=check, errors=shape_errors, llm_used=False, attempts=1,
            evidence_paths=evidence_paths,
        )

    # 自动动态路径只在调用方明确提供 route_scope 时允许自动注册；普通工具调用
    # 仍保持旧的人工闸门，避免把孤立的协议草案误当成可执行事实。
    if auto_approve and route_context:
        return SynthesisResult(
            descriptor=descriptor, status="APPROVED",
            field_check=check, llm_used=False, attempts=1, evidence_paths=evidence_paths,
        )
    # 人工闸门：默认首次合成停在这里（方案 §6.1 第 4 步）
    return SynthesisResult(
        descriptor=descriptor, status="REQUIRES_HUMAN_APPROVAL",
        field_check=check, llm_used=False, attempts=1, evidence_paths=evidence_paths,
    )


def approve_and_register(result: SynthesisResult) -> bool:
    """人工批准后入库（注册表 setdefault，同 id 不覆盖既有声明）。

    真实审批动作（终端确认/签名回执）由调用方完成；本函数只负责入库。
    """
    if result.status != "REQUIRES_HUMAN_APPROVAL" or result.descriptor is None:
        return False
    from .protocols.descriptors import register  # noqa: PLC0415

    register(result.descriptor)
    return True
