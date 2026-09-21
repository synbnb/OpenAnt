"""契约固件：DP-02（SP_daemon 命令注入）与 HV-05（FreezeManager 路径穿越）。

契约 = 六块声明（§5.1）；样本差异全部在数据里，代码零样本逻辑。
字段值经 protocols.codec 按描述符编码；run_pattern 由 runner 注入。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import (
    ArtifactForm,
    CleanupSpec,
    Contract,
    EntrySpec,
    FaultSpec,
    IdentitySpec,
    OracleSpec,
    ProtocolSpec,
    RouteBinding,
    RiskSpec,
    FieldSpec,
    Guard,
    SendTransform,
    ProtocolDescriptor,
)

_CONTRACTS_DIR = Path(__file__).parent


def load_contract(name: str) -> Contract:
    """从 JSON 固件载入契约（声明式，允许未来扩展到任意样本）。"""
    path = _CONTRACTS_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"契约固件不存在: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    return contract_from_dict(raw)


def contract_from_dict(raw: dict[str, Any]) -> Contract:
    entry = EntrySpec(**raw["entry"])
    identity = IdentitySpec(**raw["identity"])
    proto_raw = raw["protocol"]
    protocol = ProtocolSpec(
        descriptor_id=proto_raw["descriptor_id"],
        field_values=dict(proto_raw.get("field_values", {})),
        descriptor_snapshot=dict(proto_raw.get("descriptor_snapshot") or {}),
        frame_sequence=list(proto_raw.get("frame_sequence", [])),
        inter_frame_delay_seconds=float(proto_raw.get("inter_frame_delay_seconds", 0.3)),
    )
    if "param_space" in proto_raw:
        protocol.param_space = dict(proto_raw["param_space"])
    snapshot = protocol.descriptor_snapshot
    if snapshot and snapshot.get("descriptor_id"):
        try:
            from ..protocols.descriptors import get_descriptor, register

            get_descriptor(str(snapshot["descriptor_id"]))
        except KeyError:
            try:
                descriptor = ProtocolDescriptor(
                    descriptor_id=str(snapshot["descriptor_id"]),
                    endianness=str(snapshot.get("endianness", "host")),
                    framing=str(snapshot.get("framing", "single_message")),
                    transports=[str(x) for x in snapshot.get("transports", [])],
                    fields=[FieldSpec(**dict(x)) for x in snapshot.get("fields", [])],
                    known_guards=[Guard(**dict(x)) for x in snapshot.get("known_guards", [])],
                    on_send_transforms=[SendTransform(**dict(x))
                                        for x in snapshot.get("on_send_transforms", [])],
                    structure_evidence=str(snapshot.get("structure_evidence", "")),
                    encoder_kind=str(snapshot.get("encoder_kind", "custom")),
                    wire_format=dict(snapshot.get("wire_format") or {}),
                    legal_probe=dict(snapshot.get("legal_probe") or {}),
                )
                register(descriptor)
            except (TypeError, ValueError, KeyError):
                pass
    fault = FaultSpec(**raw["fault"])
    oracle_raw = raw["oracle"]
    hilog_raw = oracle_raw.get("hilog_expectations", [])
    # 不要在这里用无条件 ``list(value)``：字符串会被拆成字符，null 会在
    # 反序列化阶段直接 TypeError，二者都会绕过真正的契约格式诊断。保留
    # 原始非法形态交给 contract_validator 统一报告，确保不上设备。
    hilog_expectations = (
        list(hilog_raw) if isinstance(hilog_raw, list) else hilog_raw
    )
    oracle = OracleSpec(
        kind=oracle_raw["kind"],
        artifact_forms=[ArtifactForm(**f) for f in oracle_raw.get("artifact_forms", [])],
        hilog_expectations=hilog_expectations,
        pattern_key=oracle_raw.get("pattern_key", "run_pattern"),
        refutation=list(oracle_raw.get("refutation", [])),
        evidence=oracle_raw.get("evidence", ""),
    )
    risk = RiskSpec(**raw["risk"])
    cleanup = CleanupSpec(**raw["cleanup"])
    route_raw = raw.get("route_binding") or {}
    route_binding = RouteBinding(
        route_id=str(route_raw.get("route_id", "")),
        candidate_id=str(route_raw.get("candidate_id", "")),
        relevance=str(route_raw.get("relevance", "unknown")),
        handler=str(route_raw.get("handler", "")),
        target_sink=str(route_raw.get("target_sink", "")),
        dispatch_conditions=[str(x) for x in route_raw.get("dispatch_conditions", [])],
        state_flow=[str(x) for x in route_raw.get("state_flow", [])],
        evidence=[str(x) for x in route_raw.get("evidence", [])],
        assumptions=[str(x) for x in route_raw.get("assumptions", [])],
        missing_evidence=[str(x) for x in route_raw.get("missing_evidence", [])],
    )
    return Contract(
        contract_id=raw["contract_id"],
        finding_ids=list(raw.get("finding_ids", [])),
        unit_id=raw.get("unit_id", ""),
        vuln_class=raw.get("vuln_class", ""),
        description=raw.get("description", ""),
        entry=entry,
        identity=identity,
        protocol=protocol,
        fault=fault,
        oracle=oracle,
        risk=risk,
        cleanup=cleanup,
        route_binding=route_binding,
        limitations=list(raw.get("limitations", [])),
    )


def contract_to_json(contract: Contract) -> dict[str, Any]:
    return contract.to_dict()
