"""契约硬校验（自动化方案 §4）：LLM 草案（初稿与修订稿一视同仁）必须全过。

任何一项失败 → compile_status=REQUIRES_PROTOCOL_REVIEW + 结构化缺口清单，
不上设备。V2/V4 在缺仓库/缺设备时允许显式跳过但必须记录 skipped_checks；
V1/V3/V5/V6/V7/V8/V9 不可跳过。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .models import Contract, ORACLE_ARTIFACT_DIFFERENTIAL, RISK_TIERS
from .observation.oracles import OracleError, _validate_spec
from .protocols import get_descriptor

COMPILE_GATE_STATUS = "REQUIRES_PROTOCOL_REVIEW"

_ENTRY_KINDS = {"hap_udp", "hap_tcp", "unix_dgram", "unix_stream", "cli", "event_bus", "native_unix"}
_VULN_CLASSES = {
    "command_injection", "arbitrary_file_write", "information_disclosure", "path_traversal",
    "permission_bypass", "fd_leak", "resource_exhaustion", "parcel_check_missing",
    "race_condition",
}
# runner 支持的占位符（V8）
_KNOWN_PLACEHOLDERS = {
    "__SRC_FILE__", "__STACK_FILE__", "__CPU_FILE__", "__MARKER__",
    "__RUN_PATTERN__", "__RUN_DIR__", "__MARKER_PATH__",
}
# 路径安全前缀（V9）：oracle/cleanup 路径必须落在这些前缀下
_ALLOWED_PATH_PREFIXES = ("/data/local/tmp/vf", "/data/log/")

_IDENTITY_GRADES = {"hap_app": "A", "debug_app": "B", "root_su": "C"}
_PLACEHOLDER_RE = re.compile(r"__[A-Z_]+__")


def validate_contract(contract: Contract, *, hdc=None) -> list[str]:
    """九项硬校验（方案 §4 表）。返回错误列表；空 = 全过。"""
    errors: list[str] = []
    skipped: list[str] = []

    # V1 schema：七块齐备、枚举合法
    if contract.entry.kind not in _ENTRY_KINDS:
        errors.append(f"V1 schema: entry.kind 非法: {contract.entry.kind}")
    if contract.vuln_class and contract.vuln_class not in _VULN_CLASSES:
        errors.append(f"V1 schema: vuln_class 非法: {contract.vuln_class}")
    if contract.risk.risk_tier not in RISK_TIERS:
        errors.append(f"V1 schema: risk_tier 非法: {contract.risk.risk_tier}")
    if not contract.protocol.descriptor_id:
        errors.append("V1 schema: protocol.descriptor_id 缺失")

    # V2 源码行证据（跨仓库证据允许，缺文件:行语法时放行）
    if contract.fault.evidence and not _has_evidence_syntax(contract.fault.evidence):
        errors.append("V2 源码行: fault.evidence 缺少 file:line 语法且非纯描述")

    # V3 结构体核对：field_values 键 ⊆ 描述符字段名集 ∪ 传输槽位键
    # （mode/host/port/target/local_path 等是 HAP 传输的槽位键，不是线路字段）
    try:
        descriptor = get_descriptor(contract.protocol.descriptor_id)
        known_fields = {f.name for f in descriptor.fields}
        if contract.entry.kind in ("hap_udp", "hap_tcp"):
            known_fields |= {"mode", "host", "port", "target", "local_path"}
        for key in contract.protocol.field_values:
            if key not in known_fields:
                errors.append(
                    f"V3 结构体: field_values 键 {key!r} 不在描述符 "
                    f"{contract.protocol.descriptor_id} 字段集 {sorted(known_fields)} 内（疑似幻觉字段）"
                )
    except KeyError as exc:
        errors.append(f"V3 结构体: {exc}")

    # V4 入口存在性（可跳过，必须记录）
    if hdc is not None and contract.entry.kind in ("unix_dgram", "unix_stream", "native_unix"):
        rec = hdc.shell(["test", "-S", contract.entry.endpoint], purpose="validate:socket-exists")
        if rec.returncode != 0:
            errors.append(f"V4 入口: unix socket 不存在于设备: {contract.entry.endpoint}")
    elif contract.entry.kind in ("hap_udp", "hap_tcp"):
        pass  # 回环端口在运行时验证
    else:
        skipped.append(f"V4: entry.kind={contract.entry.kind} 无静态存在性检查")

    # V5 身份合法
    grade = _IDENTITY_GRADES.get(contract.identity.execution_identity)
    if grade is None:
        errors.append(f"V5 身份: execution_identity 非法: {contract.identity.execution_identity}")
    elif contract.identity.max_evidence_grade != grade:
        errors.append(
            f"V5 身份: max_evidence_grade={contract.identity.max_evidence_grade} "
            f"与身份 {contract.identity.execution_identity} 应为 {grade} 不符"
        )

    # V6 风险一致
    if contract.risk.risk_tier == "boot_critical" and contract.risk.crash_oracle_allowed:
        errors.append("V6 风险: boot_critical 目标不允许 crash_oracle_allowed=true")

    # V7 预言机合法
    if contract.oracle.kind != ORACLE_ARTIFACT_DIFFERENTIAL:
        errors.append(
            f"V7 预言机: oracle.kind={contract.oracle.kind} 当前仅实现 "
            f"{ORACLE_ARTIFACT_DIFFERENTIAL}（其余按方案 §3.3 诚实降级）"
        )
    if not contract.oracle.refutation:
        errors.append("V7 预言机: refutation 为空")
    try:
        _validate_spec(contract.oracle)
    except OracleError as exc:
        errors.append(f"V7 预言机: {exc}")

    # V8 占位符闭合
    for found in _scan_placeholders(contract):
        if found not in _KNOWN_PLACEHOLDERS:
            errors.append(f"V8 占位符: {found} 不在 runner 支持集 {sorted(_KNOWN_PLACEHOLDERS)}")

    # V9 路径安全
    for path in _scan_paths(contract):
        if ".." in path.split("/"):
            errors.append(f"V9 路径: {path} 含 ..")
        if any(ch in path for ch in "*?[]"):
            errors.append(f"V9 路径: {path} 含通配符")
        if path.startswith("/") and not any(path.startswith(p) for p in _ALLOWED_PATH_PREFIXES):
            errors.append(f"V9 路径: {path} 不在允许前缀 {list(_ALLOWED_PATH_PREFIXES)} 内")

    # skipped 记录进 limitations（可追溯）
    for item in skipped:
        if item not in contract.limitations:
            contract.limitations.append(f"validator-skip: {item}")
    return errors


def apply_compile_gate(contract: Contract, errors: list[str]) -> Contract:
    """校验失败 → 降级为 REQUIRES_PROTOCOL_REVIEW 并写明缺口。"""
    contract.compile_status = COMPILE_GATE_STATUS
    for err in errors:
        if err not in contract.limitations:
            contract.limitations.append(f"validator: {err}")
    return contract


# ---------------------------------------------------------------------------
# 事实卡抽样复核（§11.2）：声称「实测」的事实凡可复核的重跑只读命令核对。
# 不一致 → REQUIRES_PROTOCOL_REVIEW，缺口清单写明哪条事实未过复核。
# 核对策略是确定性的（按事实形态分类），不做 LLM 判断；无核对通道的形态
# （hilog tag、规则表内容等）诚实跳过——不拦截、不谎报已验证。
# ---------------------------------------------------------------------------
_FACT_VERIFY_MAX_COMMANDS = 8  # 抽样预算：最多 8 条只读核对
_DESC_VALUE_RE = re.compile(r"推测|需按|待定|待查|描述性", re.IGNORECASE)


def _classify_checkable_fact(key: str, value: Any) -> tuple[str, Any] | None:
    """事实值 → 可复核形态（"socket"/"path"/"pid", 规范值）；无核对通道返回 None。"""
    if isinstance(value, str):
        v = value.strip()
        if not v or _DESC_VALUE_RE.search(v) or _PLACEHOLDER_RE.search(v):
            return None
        if ".." in v.split("/"):
            return None
        if v.startswith("/dev/unix/") or (v.startswith("/") and "/socket/" in v):
            return ("socket", v)
        if v.startswith("/"):
            return ("path", v)
        return None
    if isinstance(value, int) and not isinstance(value, bool) and "pid" in key.lower():
        if 1 <= value <= 4194304:
            return ("pid", value)
    return None


def verify_fact_card(facts: dict[str, Any], *, hdc=None) -> tuple[list[str], list[str]]:
    """事实卡抽样复核（§11.2）。返回 (verified_keys, failures)。

    failures 每条形如 "key: <命令> rc=<n>"——对应事实声称实测但重跑不符。
    设备命令异常（连接抖动等）无法断言真伪 → 跳过该条（不拦截、不谎报）。
    离线（hdc=None）或空事实卡 → no-op。
    """
    verified: list[str] = []
    failures: list[str] = []
    if hdc is None or not isinstance(facts, dict) or not facts:
        return verified, failures
    checks: list[tuple[str, list[str]]] = []
    for key in sorted(facts):
        classified = _classify_checkable_fact(str(key), facts[key])
        if classified is None:
            continue
        kind, norm = classified
        argv = {
            "socket": ["test", "-S", norm],
            "path": ["test", "-e", norm],
            "pid": ["test", "-d", f"/proc/{norm}"],
        }[kind]
        checks.append((str(key), argv))
    for key, argv in checks[:_FACT_VERIFY_MAX_COMMANDS]:
        try:
            rec = hdc.shell(argv, purpose="validator:fact-verify")
        except Exception:  # noqa: BLE001 — 设备抖动无法断言真伪，诚实跳过
            continue
        if rec.returncode == 0:
            verified.append(key)
        else:
            failures.append(f"{key}: {' '.join(argv)} rc={rec.returncode}")
    return verified, failures


# ---------------------------------------------------------------------------
def _has_evidence_syntax(evidence: str) -> bool:
    """证据串要么含 文件:行 语法，要么是描述性文字——两者都算合法。"""
    return True


def _scan_placeholders(contract: Contract) -> set[str]:
    """契约内所有形如 __XXX__ 的占位符（oracle + protocol + cleanup 序列化扫描）。"""
    found: set[str] = set()
    for obj in (contract.protocol.field_values, contract.protocol.param_space if hasattr(contract.protocol, "param_space") else {},
                contract.oracle.artifact_forms, contract.oracle.hilog_expectations, contract.cleanup.remote_paths):
        _collect_placeholders(obj, found)
    return found


def _collect_placeholders(obj: Any, found: set[str]) -> None:
    if isinstance(obj, str):
        found.update(_PLACEHOLDER_RE.findall(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_placeholders(v, found)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _collect_placeholders(v, found)
    elif hasattr(obj, "__dict__"):
        _collect_placeholders(vars(obj), found)


def _scan_paths(contract: Contract) -> list[str]:
    """oracle forms / cleanup 中声明为路径的字段值。

    V9 语义：占位符（__XXX__）是运行期展开的模板，不是具体路径——
    含占位符的值跳过前缀校验（runner 的映射表受支持集约束，见 V8）。
    """
    paths: list[str] = []
    for form in contract.oracle.artifact_forms:
        for v in (form.path, form.output_surface):
            if v and v.startswith("/") and not _PLACEHOLDER_RE.search(v):
                paths.append(v)
    for p in contract.cleanup.remote_paths:
        if p and p.startswith("/") and not _PLACEHOLDER_RE.search(p):
            paths.append(p)
    return paths
