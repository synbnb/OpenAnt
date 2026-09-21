"""Native Unix-socket 传输（§9.1）。

payload 由 protocols.codec 编码为字节后落盘推送；设备侧 unix_client 负责发送，
on_send_transforms（如 patch_event_credentials）映射为客户端 CLI 开关。
逐系统调用结果回传（§9.1 硬要求）。
"""

from __future__ import annotations

import json
import re
import tempfile
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..models import ProtocolSpec, SyscallRecord
from .base import INPUT_DELIVERED, INPUT_NOT_SENT, INPUT_REJECTED, SendResult, TransportError

if TYPE_CHECKING:
    from ..hdc_client import HDCClient

_PAYLOAD_NAME = "payload.bin"
_SYSLINE_RE = re.compile(r"^\{.*\}$")


class NativeUnixTransport:
    transport_id = "native_unix"

    def __init__(self, hdc: "HDCClient", *, client_path: str | None = None) -> None:
        self.hdc = hdc
        self.client_path = client_path

    def ensure_client(self) -> str:
        if self.client_path:
            return self.client_path
        from ..native import compile_and_push

        device_path, sha = compile_and_push(self.hdc)
        self.client_path = device_path
        return device_path

    def _encode_to_file(self, protocol: ProtocolSpec, descriptor) -> Path:
        from ..protocols import encode

        blob = encode(descriptor, protocol.field_values)
        tmp = Path(tempfile.mkdtemp(prefix="vf-payload-")) / _PAYLOAD_NAME
        tmp.write_bytes(blob)
        return tmp

    def send(
        self,
        protocol: ProtocolSpec,
        descriptor,
        *,
        socket_path: str,
        frames: int = 1,
        inter_frame_delay_ms: int = 0,
        drop_privs: tuple[int, int] | None = None,
        purpose: str = "",
    ) -> SendResult:
        """编码 → 推送 → 设备侧执行 → 解析逐系统调用结果。

        drop_privs=(uid, gid)：设备侧载体先降权再发送（§12.2 身份阶梯——
        非 root 攻击者模型）。降权失败载体直接退出，绝不以 root 身份
        产出"非 root"结论。
        """
        client = self.ensure_client()
        payload_local = self._encode_to_file(protocol, descriptor)
        payload_bytes = payload_local.read_bytes()
        payload_remote = f"/data/local/tmp/vf/{_PAYLOAD_NAME}"
        self.hdc.file_send(payload_local, payload_remote, purpose="push:payload")

        transforms = {t.name for t in getattr(descriptor, "on_send_transforms", [])}
        argv = [client, socket_path, payload_remote]
        if "patch_event_credentials" in transforms:
            argv.append("--patch-event-credentials")
        if frames > 1:
            argv += ["--frames", str(frames)]
            if inter_frame_delay_ms:
                argv += ["--delay-ms", str(inter_frame_delay_ms)]
        if drop_privs is not None:
            argv += ["--drop-privs", str(drop_privs[0]), str(drop_privs[1])]

        rec = self.hdc.run(["shell", *argv], purpose=purpose or "native_unix:send")
        syscalls = _parse_syscall_lines(rec.stdout)
        result_line = next((s for s in syscalls if s.call == "result"), None)
        transport_meta = {
            "kind": self.transport_id,
            "socket_path": socket_path,
            "client": client,
            "argv": argv,
            "on_send_transforms": sorted(transforms),
            "sent_frames": [{
                "index": 1,
                "slot": "payload",
                "payload": payload_bytes.decode("utf-8", errors="replace"),
                "payload_hex": payload_bytes.hex(),
                "encoding": "UTF-8-or-binary",
                "byte_length": len(payload_bytes),
                "delay_before_seconds": 0.0,
                "source": "native_unix_encoded_payload",
            }],
            "frame_count": 1,
            "frame_note": "设备侧 unix_client 从 payload.bin 读取并向声明的 Unix socket 发送该字节序列。",
            "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        }
        if result_line is None:
            return SendResult(
                reachability=INPUT_NOT_SENT,
                detail=f"unix_client 无 result 输出 rc={rec.returncode} err={rec.stderr[-200:]}",
                syscalls=[s.to_dict() for s in syscalls],
                transport=transport_meta,
            )
        if result_line.returncode == 0:
            return SendResult(
                reachability=INPUT_DELIVERED,
                detail="delivered",
                syscalls=[s.to_dict() for s in syscalls],
                transport=transport_meta,
            )
        errno = result_line.errno
        detail = f"sendto errno={errno}"
        # EACCES/EPERM/ENOENT 属服务/策略拒绝，而非未送达基础设施故障
        if errno in (13, 1, 2, 111):
            return SendResult(
                reachability=INPUT_REJECTED,
                detail=detail,
                syscalls=[s.to_dict() for s in syscalls],
                transport=transport_meta,
            )
        return SendResult(
            reachability=INPUT_NOT_SENT,
            detail=detail,
            syscalls=[s.to_dict() for s in syscalls],
            transport=transport_meta,
        )


def _parse_syscall_lines(stdout: str) -> list[SyscallRecord]:
    out: list[SyscallRecord] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not _SYSLINE_RE.match(line):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append(SyscallRecord(
            call=str(obj.get("call", "?")),
            returncode=int(obj.get("rc", 0)),
            errno=int(obj.get("errno", 0)),
            detail=str(obj.get("detail", "")),
        ))
    return out
