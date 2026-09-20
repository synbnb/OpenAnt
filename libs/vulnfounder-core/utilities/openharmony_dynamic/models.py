"""V2 数据模型：契约 / 描述符 / 变异 / 观测 / 判定。

全部为纯数据类 + to_dict，不包含设备访问。见
docs/VULNFOUNDER_DYNAMIC_TEST_REWRITE_PLAN.zh-CN.md §5。
"""

from __future__ import annotations

import time
import uuid
import hashlib
from dataclasses import dataclass, field
from typing import Any


def utc_now() -> float:
    return time.time()


def new_run_id() -> str:
    stamp = time.strftime("%Y%m%d%H%M%S", time.localtime())
    return f"vf-{stamp}-{uuid.uuid4().hex[:6]}"


# ---------------------------------------------------------------------------
# 协议描述符（声明式，一个协议族一份）
# ---------------------------------------------------------------------------

@dataclass
class FieldSpec:
    name: str
    type: str                       # "string" | "int64" | "double" | "bool" | "u32" | "u64"
    order: int = 0
    evidence: str = ""
    case_sensitive: bool = False    # raw_key_overrides 通道
    required: bool = False
    default: Any = None


@dataclass
class Guard:
    name: str
    evidence: str
    checked_by: str
    # 设备侧日志关键词（试跑-修正闭环的 guard_rejections 依据，方案 §5.3）
    guard_log_hints: list[str] = field(default_factory=list)


@dataclass
class SendTransform:
    name: str                       # 例如 patch_event_credentials
    kind: str                       # device_side_credential_patch / ...
    evidence: str = ""


@dataclass
class ProtocolDescriptor:
    descriptor_id: str
    endianness: str = "host"
    framing: str = "single_message"
    transports: list[str] = field(default_factory=list)
    fields: list[FieldSpec] = field(default_factory=list)
    known_guards: list[Guard] = field(default_factory=list)
    on_send_transforms: list[SendTransform] = field(default_factory=list)
    structure_evidence: str = ""
    # 通用协议编码器声明。内置描述符可以继续使用既有编码器；自动发现的
    # 描述符必须声明可解释的 wire_format，避免把协议族名称写死在运行器中。
    encoder_kind: str = "custom"       # raw_text | key_value | json | custom
    wire_format: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "descriptor_id": self.descriptor_id,
            "endianness": self.endianness,
            "framing": self.framing,
            "transports": list(self.transports),
            "fields": [f.__dict__ for f in self.fields],
            "known_guards": [g.__dict__ for g in self.known_guards],
            "on_send_transforms": [t.__dict__ for t in self.on_send_transforms],
            "structure_evidence": self.structure_evidence,
            "encoder_kind": self.encoder_kind,
            "wire_format": dict(self.wire_format),
        }


# ---------------------------------------------------------------------------
# 契约（六块：entry / identity / protocol / fault / oracle / cleanup）
# ---------------------------------------------------------------------------

# oracle.kind 枚举
ORACLE_ARTIFACT_DIFFERENTIAL = "artifact_differential"
ORACLE_HILOG_EXPECTATION = "hilog_expectation"
ORACLE_READBACK_DIFFERENTIAL = "readback_differential"
ORACLE_PERMISSION_DIFFERENTIAL = "permission_differential"
ORACLE_CRASH_CORRELATED = "crash_correlated"
ORACLE_RESOURCE_DELTA = "resource_delta"
ORACLE_STATE_DIFFERENTIAL = "state_differential"
ORACLE_PROCESS_LIVENESS = "process_liveness"

RISK_TIERS = ("boot_critical", "restartable_service", "user_daemon", "unknown")

COMPILE_STATUSES = (
    "ELIGIBLE",
    "REQUIRES_PROTOCOL_REVIEW",
    "REQUIRES_IDENTITY_SYNTHESIS",
    "REQUIRES_UNSUPPORTED_FIRMWARE_FEATURE",
    "REQUIRES_ARTIFACT",
    "ORACLE_UNAVAILABLE",
    "SOURCE_FIRMWARE_MISMATCH",
    "NEEDS_HUMAN_APPROVAL",
)


@dataclass
class EntrySpec:
    kind: str                        # hap_udp | hap_tcp | unix_dgram | unix_stream | cli | event_bus
    endpoint: str = ""
    reachability_identity: str = "root_su"
    evidence: str = ""


@dataclass
class IdentitySpec:
    execution_identity: str = "root_su"
    identity_ladder_fallback: str = "root_su"
    max_evidence_grade: str = "C"
    # 降权发送（§12.2 身份阶梯）：(uid, gid) 非空时设备侧载体先 setresuid/setresgid
    # 再发送——攻击者模型为非 root 身份。载体降权失败即退出，绝不以 root 冒充非 root。
    drop_privs: tuple[int, int] | None = None


@dataclass
class ProtocolSpec:
    descriptor_id: str
    field_values: dict[str, Any] = field(default_factory=dict)
    # 编译时使用的协议描述符快照，便于脱离当前进程注册表重放契约。
    descriptor_snapshot: dict[str, Any] = field(default_factory=dict)
    # 发送序列：多帧时按顺序；单帧省略。帧之间固定间隔秒数。
    frame_sequence: list[str] = field(default_factory=list)   # 字段值组合的键名列表
    inter_frame_delay_seconds: float = 0.3


@dataclass
class RouteBinding:
    """某个 finding 在一个外部入口上的路由切片。

    ProtocolDescriptor 描述协议族，RouteBinding 描述本次 finding 实际要走的
    endpoint、handler、分派条件和状态读写。两者分离后，同一服务的其它入口不会
    被错误拼进当前样本的动态测试契约。
    """

    route_id: str = ""
    candidate_id: str = ""
    relevance: str = "unknown"  # direct | possible | unrelated | unknown
    handler: str = ""
    target_sink: str = ""
    dispatch_conditions: list[str] = field(default_factory=list)
    state_flow: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_id": self.route_id,
            "candidate_id": self.candidate_id,
            "relevance": self.relevance,
            "handler": self.handler,
            "target_sink": self.target_sink,
            "dispatch_conditions": list(self.dispatch_conditions),
            "state_flow": list(self.state_flow),
            "evidence": list(self.evidence),
            "assumptions": list(self.assumptions),
            "missing_evidence": list(self.missing_evidence),
        }

    @staticmethod
    def make_id(finding_id: str, candidate_id: str, sink: str) -> str:
        material = f"{finding_id}|{candidate_id}|{sink}".encode("utf-8", "replace")
        return "route-" + hashlib.sha256(material).hexdigest()[:16]


@dataclass
class FaultSpec:
    operator: str                     # payload_value_substitution | frame_pair | ...
    description: str = ""
    evidence: str = ""
    expected_guards: list[str] = field(default_factory=list)   # 静态推演的门槛，仅对照用


@dataclass
class ArtifactForm:
    # artifact_differential 四形态
    form: str                         # create | exfil | delete | attr
    path: str = ""                    # create/delete/attr 的观测路径；exfil 的预埋文件路径
    content_contains: str = ""        # create 验证内容 / exfil 预埋内容
    output_surface: str = ""          # exfil：输出面路径（如 freeze_ext 文件 glob）
    output_is_dir: bool = True


@dataclass
class OracleSpec:
    kind: str = ORACLE_ARTIFACT_DIFFERENTIAL
    artifact_forms: list[ArtifactForm] = field(default_factory=list)
    hilog_expectations: list[dict[str, Any]] = field(default_factory=list)
    pattern_key: str = "run_pattern"             # 观测值中携带 run 唯一图案的键
    refutation: list[str] = field(default_factory=list)
    evidence: str = ""


@dataclass
class CleanupSpec:
    remote_paths: list[str] = field(default_factory=list)
    restore_actions: list[str] = field(default_factory=list)
    verify: list[str] = field(default_factory=list)


@dataclass
class RiskSpec:
    target_process: str
    risk_tier: str = "unknown"
    crash_oracle_allowed: bool = False
    restartable: bool = False
    rationale: str = ""


@dataclass
class Contract:
    contract_id: str
    finding_ids: list[str]
    unit_id: str
    vuln_class: str
    entry: EntrySpec
    identity: IdentitySpec
    protocol: ProtocolSpec
    fault: FaultSpec
    oracle: OracleSpec
    risk: RiskSpec
    cleanup: CleanupSpec
    route_binding: RouteBinding = field(default_factory=RouteBinding)
    compile_status: str = "REQUIRES_PROTOCOL_REVIEW"
    limitations: list[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vf.ohos.dynamic.contract.v2",
            "contract_id": self.contract_id,
            "finding_ids": list(self.finding_ids),
            "unit_id": self.unit_id,
            "vuln_class": self.vuln_class,
            "description": self.description,
            "entry": self.entry.__dict__,
            "identity": self.identity.__dict__,
            "protocol": {
                "descriptor_id": self.protocol.descriptor_id,
                "field_values": dict(self.protocol.field_values),
                **({"descriptor_snapshot": dict(self.protocol.descriptor_snapshot)}
                   if self.protocol.descriptor_snapshot else {}),
                "frame_sequence": list(self.protocol.frame_sequence),
                "inter_frame_delay_seconds": self.protocol.inter_frame_delay_seconds,
                # param_space：非线路字段（帧模板/预埋目录/效果窗口），round-trip 必须保留
                **({"param_space": dict(self.protocol.param_space)}
                   if getattr(self.protocol, "param_space", None) else {}),
            },
            "fault": self.fault.__dict__,
            "oracle": {
                "kind": self.oracle.kind,
                "artifact_forms": [f.__dict__ for f in self.oracle.artifact_forms],
                "hilog_expectations": list(self.oracle.hilog_expectations),
                "pattern_key": self.oracle.pattern_key,
                "refutation": list(self.oracle.refutation),
                "evidence": self.oracle.evidence,
            },
            "risk": self.risk.__dict__,
            "cleanup": self.cleanup.__dict__,
            "route_binding": self.route_binding.to_dict(),
            "compile_status": self.compile_status,
            "limitations": list(self.limitations),
        }


# ---------------------------------------------------------------------------
# 观测与判定
# ---------------------------------------------------------------------------

@dataclass
class SyscallRecord:
    call: str
    returncode: int
    errno: int = 0
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "call": self.call,
            "returncode": self.returncode,
            "errno": self.errno,
            "detail": self.detail,
        }


@dataclass
class Observation:
    observation_id: str
    run_id: str
    contract_id: str
    phase: str                       # baseline | mutated
    started_at: float = field(default_factory=utc_now)
    finished_at: float = 0.0
    transport: dict[str, Any] = field(default_factory=dict)
    syscalls: list[SyscallRecord] = field(default_factory=list)
    payload_sha256: str = ""
    payload_len: int = 0
    # 四类观测面
    filesystem: dict[str, Any] = field(default_factory=dict)     # 路径 → stat/content 摘要
    hilog_hits: list[dict[str, Any]] = field(default_factory=list)
    process_state: dict[str, Any] = field(default_factory=dict)
    response_excerpt: str = ""

    def finish(self) -> None:
        if not self.finished_at:
            self.finished_at = utc_now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "run_id": self.run_id,
            "contract_id": self.contract_id,
            "phase": self.phase,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "transport": dict(self.transport),
            "syscalls": [s.__dict__ for s in self.syscalls],
            "payload_sha256": self.payload_sha256,
            "payload_len": self.payload_len,
            "filesystem": dict(self.filesystem),
            "hilog_hits": list(self.hilog_hits),
            "process_state": dict(self.process_state),
            "response_excerpt": self.response_excerpt,
        }


@dataclass
class OracleResult:
    kind: str
    effect_observed: bool
    forms: dict[str, bool] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    refutation_checks: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Verdict:
    contract_id: str
    run_id: str
    reachability: str                # INPUT_DELIVERED / INPUT_REJECTED / INPUT_NOT_SENT
    influence: str                   # SINK_CONTROLLED / SINK_REACHED_UNCONTROLLED / SINK_UNKNOWN
    effect: str                      # EFFECT_OBSERVED / EFFECT_ABSENT / EFFECT_UNKNOWN
    status: str                      # CONFIRMED / NOT_REPRODUCED / UNPROVEN_INPUT_INFLUENCE / INCONCLUSIVE / BLOCKED
    influence_blocker: str = ""      # policy / check / permission / ""
    status_reason_code: str = ""
    evidence_grade: str = "E"
    oracle: OracleResult | None = None
    code_deviation: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    gap: str = ""
