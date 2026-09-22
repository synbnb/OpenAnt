"""OpenHarmony 动态验证的 L0 设备前置确认。

本模块只做只读采集，不启动服务、不安装载荷，也不修改设备状态。它把
"当前设备到底是什么、目标服务是否存在、当前端点是否监听" 与后面的
协议恢复和 PoC 触发分开，避免把环境不匹配误判成协议或预言机失败。

设计原则：

* 不依赖某个固定服务名、端口或仓库；目标名称和端点由当前 finding/入口
  线索传入，未提供目标时只报告设备全局事实；
* HDC 的每条命令都通过 HDCClient 参数数组执行，失败保留为可审计的
  ``command_errors``，不把缺失事实伪装成“没有”；
* ``MATCHED`` 只在版本和目标服务证据都足够时使用，未知信息不会被强行
  判定为匹配；
* 输出可直接保存为 ``device_fingerprint.json``，也是后续 Agent Loop 的
  只读设备上下文输入。
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


MATCHED = "MATCHED"
MISMATCH = "MISMATCH"
UNKNOWN = "UNKNOWN"
SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
VERSION_UNVERIFIED = "VERSION_UNVERIFIED"

_HEX_PORT_RE = re.compile(r"(?P<addr>[0-9A-Fa-f]{8,32}):(?P<port>[0-9A-Fa-f]{4})")
_IP_PORT_RE = re.compile(r"(?P<host>\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:]+\]):(?P<port>\d{1,5})")
_PID_RE = re.compile(r"\b(\d+)\b")
_KEY_VALUE_RE = re.compile(r"^\s*([^=\s]+)\s*=\s*(.*?)\s*$")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def normalize_endpoint(value: str) -> str:
    """统一 Unix 路径和 TCP/UDP 端点的展示形式。"""
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.replace("TCP ", "").replace("UDP ", "").strip()
    return text


def extract_targets(values: Iterable[str] | None) -> tuple[list[str], list[str]]:
    """从入口线索中提取候选进程名和端点。

    这里只做形状识别，不判断语义。进程名使用常见的进程名形状以及
    ``daemon/server/service`` 后缀，不能把任意自然语言单词当成进程；真正
    的关联关系仍以设备输出为准。
    """
    processes: list[str] = []
    endpoints: list[str] = []
    for raw in values or []:
        text = str(raw or "")
        for path in re.findall(r"/dev/(?:unix/socket|socket)/[A-Za-z0-9_.@-]+", text):
            if path not in endpoints:
                endpoints.append(path)
        for match in _IP_PORT_RE.finditer(text):
            endpoint = f"{match.group('host')}:{match.group('port')}"
            if endpoint not in endpoints:
                endpoints.append(endpoint)
        # 只保留明显的进程标识候选，不把入口类型、协议和常见字段名当成 PID。
        for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_.-]{2,}\b", text):
            low = token.lower()
            if (low.endswith(("daemon", "server", "service"))
                    or "profiler" in low or "faultlogger" in low
                    or "appspawn" in low or low.endswith("d")):
                if token not in processes:
                    processes.append(token)
    return processes[:32], endpoints[:64]


def parse_properties(text: str) -> dict[str, str]:
    """解析 ``getprop`` 或 key=value 风格的系统属性。"""
    result: dict[str, str] = {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # OpenHarmony/Android getprop 常见格式：[key]: [value]
        match = re.match(r"^\[([^]]+)\]:\s*\[([^]]*)\]$", line)
        if match:
            result[match.group(1)] = match.group(2)
            continue
        match = _KEY_VALUE_RE.match(line)
        if match:
            result[match.group(1)] = match.group(2).strip().strip('"')
    return result


def _decode_proc_address(value: str, *, ipv6: bool = False) -> str:
    """解析 /proc/net/tcp* 的十六进制地址，失败时保留原值。"""
    try:
        if ipv6:
            raw = bytes.fromhex(value)
            # /proc/net/tcp6 以 32 位小端块表示地址；按块反转得到可读地址。
            chunks = [raw[i:i + 4][::-1] for i in range(0, len(raw), 4)]
            import ipaddress

            return str(ipaddress.IPv6Address(b"".join(chunks)))
        raw = bytes.fromhex(value)
        return ".".join(str(x) for x in raw[::-1])
    except (ValueError, ImportError):
        return value


def parse_proc_net_table(text: str, protocol: str) -> list[dict[str, Any]]:
    """解析 /proc/net/tcp、tcp6、udp、udp6 的监听/绑定条目。"""
    rows: list[dict[str, Any]] = []
    ipv6 = protocol.endswith("6")
    base_protocol = protocol.rstrip("6").lower()
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("sl"):
            continue
        columns = line.split()
        if len(columns) < 4:
            continue
        local = columns[1]
        match = _HEX_PORT_RE.fullmatch(local)
        if not match:
            continue
        host = _decode_proc_address(match.group("addr"), ipv6=ipv6)
        try:
            port = int(match.group("port"), 16)
        except ValueError:
            continue
        state_code = columns[3].upper() if len(columns) > 3 else ""
        if base_protocol == "tcp":
            state = {"01": "CONNECTED", "0A": "LISTENING"}.get(state_code, state_code or "UNKNOWN")
        else:
            # UDP 没有 TCP 意义上的 LISTEN 状态；非零 local endpoint 表示已绑定。
            state = "BOUND" if host or port else "UNKNOWN"
        rows.append({
            "protocol": base_protocol.upper(),
            "family": "AF_INET6" if ipv6 else "AF_INET",
            "host": host,
            "port": port,
            "endpoint": f"[{host}]:{port}" if ipv6 else f"{host}:{port}",
            "state": state,
            "state_code": state_code,
            "raw": line,
        })
    return rows


def parse_proc_net_unix(text: str) -> list[dict[str, Any]]:
    """解析 /proc/net/unix，保留命名和匿名 Unix socket 的区别。"""
    rows: list[dict[str, Any]] = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("num"):
            continue
        columns = line.split()
        # Num RefCount Protocol Flags Type St Inode [Path]
        if len(columns) < 7:
            continue
        path = columns[7] if len(columns) > 7 else ""
        state = columns[5].upper() if len(columns) > 5 else ""
        rows.append({
            "family": "AF_UNIX",
            "type": columns[4] if len(columns) > 4 else "",
            "state": "LISTENING" if "LISTEN" in state or state in {"01", "02"} else state or "UNKNOWN",
            "inode": columns[6] if len(columns) > 6 else "",
            "path": path,
            "named": bool(path),
            "raw": line,
        })
    return rows


def parse_ps(text: str) -> list[dict[str, str]]:
    """尽量兼容 OpenHarmony ``ps -A`` 的表格输出。"""
    rows: list[dict[str, str]] = []
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    for line in lines:
        if line.lower().startswith(("uid", "pid", "user")) and "cmd" in line.lower():
            continue
        columns = line.split()
        if not columns:
            continue
        pid_index = next((i for i, value in enumerate(columns) if value.isdigit()), None)
        if pid_index is None:
            continue
        pid = columns[pid_index]
        uid = columns[0] if pid_index > 0 else ""
        name = columns[-1]
        if name in {"-", "?"} and len(columns) > pid_index + 1:
            name = columns[pid_index + 1]
        rows.append({"pid": pid, "uid": uid, "name": name, "raw": line})
    return rows


def parse_identity(text: str) -> dict[str, str]:
    """解析 ``id`` 或 ``/proc/<pid>/attr/current`` 的最小身份字段。"""
    value = str(text or "").strip()
    result: dict[str, str] = {"raw": value}
    uid = re.search(r"\buid=(\d+)(?:\(([^)]+)\))?", value)
    if uid:
        result["uid"] = uid.group(1)
        if uid.group(2):
            result["user"] = uid.group(2)
    if value and "raw" not in result:
        result["raw"] = value
    return result


def _record_output(record: Any) -> str:
    return str(getattr(record, "stdout", "") or "")


@dataclass
class ServiceObservation:
    target: str
    kind: str = "unknown"
    present: bool | None = None
    running: bool | None = None
    pids: list[str] = field(default_factory=list)
    uid: str = ""
    selinux_domain: str = ""
    binary_path: str = ""
    binary_sha256: str = ""
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind,
            "present": self.present,
            "running": self.running,
            "pids": list(self.pids),
            "uid": self.uid,
            "selinux_domain": self.selinux_domain,
            "binary_path": self.binary_path,
            "binary_sha256": self.binary_sha256,
            "endpoints": list(self.endpoints),
            "evidence": list(self.evidence),
            "reason": self.reason,
        }


@dataclass
class DeviceFingerprint:
    serial: str
    observed_at: str = field(default_factory=_now)
    system: dict[str, str] = field(default_factory=dict)
    identity: dict[str, str] = field(default_factory=dict)
    processes: list[dict[str, str]] = field(default_factory=list)
    unix_sockets: list[dict[str, Any]] = field(default_factory=list)
    inet_sockets: list[dict[str, Any]] = field(default_factory=list)
    services: list[ServiceObservation] = field(default_factory=list)
    expected_targets: list[str] = field(default_factory=list)
    source_revision: str = ""
    device_revision: str = ""
    command_errors: list[dict[str, str]] = field(default_factory=list)
    command_count: int = 0
    raw_hashes: dict[str, str] = field(default_factory=dict)
    status: str = UNKNOWN
    status_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vf.device_fingerprint.v1",
            "serial": self.serial,
            "observed_at": self.observed_at,
            "system": dict(self.system),
            "identity": dict(self.identity),
            "processes": list(self.processes),
            "unix_sockets": list(self.unix_sockets),
            "inet_sockets": list(self.inet_sockets),
            "services": [item.to_dict() for item in self.services],
            "expected_targets": list(self.expected_targets),
            "source_revision": self.source_revision,
            "device_revision": self.device_revision,
            "command_errors": list(self.command_errors),
            "command_count": self.command_count,
            "raw_hashes": dict(self.raw_hashes),
            "status": self.status,
            "status_reasons": list(self.status_reasons),
        }


def _source_revision(repo_root: str | Path | None) -> str:
    if not repo_root:
        return ""
    try:
        proc = subprocess.run(
            ["git", "-C", str(Path(repo_root).expanduser().resolve()), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            timeout=3, check=False,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _match_endpoint(target: str, unix_rows: list[dict[str, Any]], inet_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    target = normalize_endpoint(target)
    if not target:
        return []
    if target.startswith("/"):
        return [row for row in unix_rows if row.get("path") == target]
    return [row for row in inet_rows if row.get("endpoint") == target or row.get("endpoint", "").replace("[", "").replace("]", "") == target]


def _classify(
    fingerprint: DeviceFingerprint,
    *,
    reference: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    reference = reference or {}
    reasons: list[str] = []
    expected_source = str(reference.get("source_revision") or "").strip()
    expected_device = str(reference.get("device_revision") or "").strip()
    if expected_source and fingerprint.source_revision and expected_source != fingerprint.source_revision:
        reasons.append(f"源码版本不匹配：期望 {expected_source}，当前 {fingerprint.source_revision}")
        return MISMATCH, reasons
    if expected_device and fingerprint.device_revision and expected_device != fingerprint.device_revision:
        reasons.append(f"设备版本不匹配：期望 {expected_device}，当前 {fingerprint.device_revision}")
        return MISMATCH, reasons
    if expected_source and not fingerprint.source_revision:
        reasons.append("无法取得当前源码版本")
        return VERSION_UNVERIFIED, reasons
    if expected_device and not fingerprint.device_revision:
        reasons.append("设备版本字段缺失，不能宣称版本一致")
        return VERSION_UNVERIFIED, reasons
    unavailable = [item for item in fingerprint.services if item.present is False]
    if unavailable:
        reasons.extend(f"目标未发现或未监听：{item.target}" for item in unavailable)
        return SERVICE_UNAVAILABLE, reasons
    if fingerprint.command_errors:
        reasons.append("部分设备事实采集命令失败，结果只能作为未知")
        return UNKNOWN, reasons
    if expected_source or expected_device:
        return MATCHED, ["版本字段和目标服务证据均通过"]
    return VERSION_UNVERIFIED, ["未提供可比对的源码或设备版本基线"]


def collect_device_fingerprint(
    hdc: Any,
    *,
    targets: Iterable[str] | None = None,
    process_names: Iterable[str] | None = None,
    source_revision: str = "",
    reference: dict[str, Any] | None = None,
    repo_root: str | Path | None = None,
    max_processes: int = 32,
) -> DeviceFingerprint:
    """通过 HDC 只读采集设备指纹和目标服务状态。"""
    serial = str(getattr(hdc, "serial", "") or "unknown")
    target_list = [normalize_endpoint(x) for x in (targets or []) if normalize_endpoint(x)]
    explicit_processes = [str(x).strip() for x in (process_names or []) if str(x).strip()]
    process_names_from_targets, endpoints_from_targets = extract_targets([*target_list, *explicit_processes])
    explicit_processes = list(dict.fromkeys([*explicit_processes, *process_names_from_targets]))[:32]
    target_list = list(dict.fromkeys([*target_list, *endpoints_from_targets]))[:64]
    fp = DeviceFingerprint(
        serial=serial,
        expected_targets=target_list,
        source_revision=source_revision or _source_revision(repo_root),
    )
    outputs: dict[str, str] = {}

    def run(label: str, argv: list[str]) -> str:
        try:
            rec = hdc.shell(argv, purpose=f"preflight:{label}")
            fp.command_count += 1
            out = _record_output(rec)
            outputs[label] = out
            if getattr(rec, "returncode", 0) != 0:
                fp.command_errors.append({"command": label, "error": str(getattr(rec, "stderr", "") or "returncode")})
            return out
        except Exception as exc:  # noqa: BLE001 — 指纹失败必须保留为 UNKNOWN
            fp.command_errors.append({"command": label, "error": f"{type(exc).__name__}: {exc}"})
            return ""

    props = run("getprop", ["getprop"])
    fp.system.update(parse_properties(props))
    uname = run("uname", ["uname", "-a"]).strip()
    if uname:
        fp.system["uname"] = uname
    fp.device_revision = (
        fp.system.get("ro.build.version.release")
        or fp.system.get("ro.build.version.incremental")
        or fp.system.get("ro.build.id")
        or ""
    )
    fp.identity = parse_identity(run("identity", ["id"]))
    ps_rows = parse_ps(run("ps", ["ps", "-A"]))
    fp.processes = ps_rows
    fp.unix_sockets = parse_proc_net_unix(run("unix", ["cat", "/proc/net/unix"]))
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        fp.inet_sockets.extend(parse_proc_net_table(run(proto, ["cat", f"/proc/net/{proto}"]), proto))

    by_name: dict[str, list[dict[str, str]]] = {}
    for row in ps_rows:
        by_name.setdefault(row.get("name", ""), []).append(row)
    for process in explicit_processes[:max_processes]:
        rows = by_name.get(process, [])
        observation = ServiceObservation(
            target=process,
            kind="process",
            present=bool(rows),
            running=bool(rows),
            pids=[str(item.get("pid", "")) for item in rows if item.get("pid")],
            uid=str(rows[0].get("uid", "")) if rows else "",
            evidence=["ps -A"],
            reason="进程存在并运行" if rows else "ps -A 未找到该进程",
        )
        for pid in observation.pids[:4]:
            attr = run(f"selinux:{pid}", ["cat", f"/proc/{pid}/attr/current"]).strip()
            if attr:
                observation.selinux_domain = attr
                observation.evidence.append(f"/proc/{pid}/attr/current")
                break
        if observation.pids:
            # 版本核对只读采集：先从 proc 得到设备真实可执行文件，再尝试
            # sha256sum。任何失败都保留空值/命令错误，不把路径或哈希猜出来。
            exe = run(f"exe:{observation.pids[0]}", ["readlink", f"/proc/{observation.pids[0]}/exe"]).strip()
            if exe:
                observation.binary_path = exe
                observation.evidence.append(f"/proc/{observation.pids[0]}/exe")
                digest = run(f"sha256:{observation.pids[0]}", ["sha256sum", exe]).strip()
                digest_match = re.match(r"^([0-9A-Fa-f]{64})\b", digest)
                if digest_match:
                    observation.binary_sha256 = digest_match.group(1).lower()
        fp.services.append(observation)

    for target in target_list:
        matches = _match_endpoint(target, fp.unix_sockets, fp.inet_sockets)
        kind = "unix" if target.startswith("/") else "inet"
        fp.services.append(ServiceObservation(
            target=target,
            kind=kind,
            present=bool(matches),
            running=bool(matches),
            endpoints=matches,
            evidence=[f"/proc/net/{'unix' if kind == 'unix' else 'tcp/udp'}"],
            reason="端点存在" if matches else "设备网络表中未找到该端点",
        ))

    # 将原始命令输出只保存摘要哈希，避免把完整进程/网络表重复塞进每个模型提示。
    fp.raw_hashes = {key: _sha256(value) for key, value in outputs.items() if value}
    fp.status, fp.status_reasons = _classify(fp, reference=reference)
    return fp


def persist_fingerprint(path: str | Path, fingerprint: DeviceFingerprint | dict[str, Any]) -> Path:
    """原子写入 device_fingerprint.json。"""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = fingerprint.to_dict() if isinstance(fingerprint, DeviceFingerprint) else dict(fingerprint)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(target)
    return target


__all__ = [
    "MATCHED", "MISMATCH", "UNKNOWN", "SERVICE_UNAVAILABLE", "VERSION_UNVERIFIED",
    "DeviceFingerprint", "ServiceObservation", "collect_device_fingerprint",
    "extract_targets", "normalize_endpoint", "parse_properties", "parse_ps",
    "parse_proc_net_table", "parse_proc_net_unix", "persist_fingerprint",
]
