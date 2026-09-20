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
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import FieldSpec, Guard, ProtocolDescriptor, SendTransform

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
    "}\n"
    "硬规则：\n"
    "1. fields[].name 必须逐字出现在源码 struct 定义或键常量表中——会被 grep 核对，"
    "编造一个字段整份草案作废。\n"
    "2. 每个 known_guard 必须带源码行证据。\n"
    "3. 只输出一个 JSON 对象。"
)


@dataclass
class SynthesisResult:
    """合成结果：approved 前永远停在 REQUIRES_HUMAN_APPROVAL。"""

    descriptor: ProtocolDescriptor | None
    status: str                        # REQUIRES_HUMAN_APPROVAL / REJECTED_FIELD_CHECK / REQUIRES_PROTOCOL_REVIEW / APPROVED
    field_check: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    llm_used: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "field_check": dict(self.field_check),
            "errors": list(self.errors),
            "llm_used": self.llm_used,
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
    repo = Path(repo_root) if repo_root else None
    for src in source_paths:
        path = Path(src) if Path(src).is_absolute() else (repo / src if repo else Path(src))
        text = _read_source(path)
        if text:
            sources.append(text)
    verified: list[str] = []
    missing: list[str] = []
    for f in descriptor.fields:
        if not f.name:
            missing.append(f.name)
            continue
        if any(f.name in text for text in sources):
            verified.append(f.name)
        else:
            missing.append(f.name)
    return {
        "verified": verified,
        "missing": missing,
        "sources_read": [f"{p}" for p in source_paths],
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
        )
    except (KeyError, TypeError, ValueError):
        return None


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
) -> SynthesisResult:
    """源码 → ProtocolDescriptor 草案 → 字段核对 → 人工闸门。

    draft_override 用于测试注入（跳过 LLM）。
    """
    repo = Path(repo_root) if repo_root else None
    texts: list[str] = []
    for src in source_paths:
        path = Path(src) if Path(src).is_absolute() else (repo / src if repo else Path(src))
        texts.append(_read_source(path))
    if not any(texts):
        return SynthesisResult(
            descriptor=None, status="REQUIRES_PROTOCOL_REVIEW",
            errors=["全部源码文件不可读，无法合成"],
        )

    raw = draft_override or _llm_descriptor_draft(
        texts, source_names=source_paths, route_context=route_context,
    )
    if raw is None:
        return SynthesisResult(
            descriptor=None, status="REQUIRES_PROTOCOL_REVIEW",
            errors=["LLM 不可用或输出不合法"], llm_used=draft_override is None,
        )

    descriptor = _descriptor_from_draft(raw)
    if descriptor is None:
        return SynthesisResult(
            descriptor=None, status="REQUIRES_PROTOCOL_REVIEW",
            errors=["草案缺必填键（descriptor_id/fields）或类型不符"],
            llm_used=draft_override is None,
        )

    if descriptor_id_override:
        descriptor.descriptor_id = descriptor_id_override
    if descriptor.encoder_kind not in {"raw_text", "key_value", "json", "custom"}:
        return SynthesisResult(
            descriptor=descriptor, status="REQUIRES_PROTOCOL_REVIEW",
            errors=[f"不支持的 encoder_kind: {descriptor.encoder_kind}"],
            llm_used=draft_override is None,
        )

    # 确定性核对：字段名逐一 grep（方案 §6.1 第 2 步）
    check = verify_fields_against_source(descriptor, source_paths, repo_root=repo_root)
    if check["missing"] or not check["verified"]:
        return SynthesisResult(
            descriptor=descriptor, status="REJECTED_FIELD_CHECK",
            field_check=check,
            errors=[f"字段核对失败（疑似幻觉字段）: {check['missing']}"],
            llm_used=draft_override is None,
        )

    # 自动动态路径只在调用方明确提供 route_scope 时允许自动注册；普通工具调用
    # 仍保持旧的人工闸门，避免把孤立的协议草案误当成可执行事实。
    if auto_approve and route_context:
        return SynthesisResult(
            descriptor=descriptor, status="APPROVED",
            field_check=check, llm_used=draft_override is None,
        )
    # 人工闸门：默认首次合成停在这里（方案 §6.1 第 4 步）
    return SynthesisResult(
        descriptor=descriptor, status="REQUIRES_HUMAN_APPROVAL",
        field_check=check, llm_used=draft_override is None,
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
