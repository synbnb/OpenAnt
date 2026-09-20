"""统一 HDC 调用层。

约束（§15 安全边界）：
- 主机侧永远 shell=False，参数数组构造；
- 强制 -t <serial>，杜绝误操作其它设备；
- 每条命令落入台账（脱敏）；
- 单命令超时。
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SERIAL_RE = re.compile(r"[0-9A-Za-z]{16,64}")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
# 台账脱敏：疑似敏感 token 值
_SENSITIVE_KV_RE = re.compile(r"(password|passwd|token|secret)=([^\s]+)", re.IGNORECASE)


@dataclass
class CommandRecord:
    index: int
    argv: list[str]
    purpose: str
    returncode: int
    stdout: str
    stderr: str
    elapsed_ms: int
    truncated: bool
    stdout_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "argv": list(self.argv),
            "purpose": self.purpose,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "elapsed_ms": self.elapsed_ms,
            "truncated": self.truncated,
            "stdout_sha256": self.stdout_sha256,
        }


def sanitize(text: str) -> str:
    return _SENSITIVE_KV_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)


class HDCError(RuntimeError):
    """HDC 基础层失败（找不到 hdc / server 异常 / 设备离线 / 超时）。"""


class HDCClient:
    def __init__(
        self,
        hdc_path: str,
        serial: str,
        *,
        ledger_path: Path | None = None,
        timeout_seconds: int = 30,
        max_output_bytes: int = 262144,
        on_command: "callable | None" = None,
    ) -> None:
        if not _SERIAL_RE.fullmatch(serial or ""):
            raise HDCError(f"非法设备 serial: {serial!r}")
        self.hdc_path = hdc_path
        self.serial = serial
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self._ledger: list[CommandRecord] = []
        self._lock = threading.Lock()
        self.ledger_path = ledger_path
        # 可选回调：每条设备命令完成后调用 record.to_dict()（实时进度展示用）
        self.on_command = on_command

    # ------------------------------------------------------------------
    def _run_host(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        try:
            completed = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise HDCError(f"HDC 命令超时（{timeout}s）: {argv[:4]}") from exc
        except OSError as exc:
            raise HDCError(f"HDC 无法执行: {exc}") from exc
        return (
            completed.returncode,
            completed.stdout.decode("utf-8", errors="replace"),
            completed.stderr.decode("utf-8", errors="replace"),
        )

    def run(self, remote_argv: list[str], *, purpose: str = "", timeout_seconds: int | None = None,
            use_serial: bool = True) -> CommandRecord:
        """执行一条设备命令（参数数组，不经 shell 拼接）。"""
        if not remote_argv or not all(isinstance(a, str) for a in remote_argv):
            raise HDCError("远端命令必须是字符串数组")
        joined = " ".join(remote_argv)
        if "\x00" in joined:
            raise HDCError("远端命令包含 NUL")
        timeout = timeout_seconds or self.timeout_seconds
        argv = [self.hdc_path]
        if use_serial:
            argv += ["-t", self.serial]
        argv += remote_argv
        started = time.monotonic()
        rc, out, err = self._run_host(argv, timeout)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        truncated = False
        if len(out) > self.max_output_bytes:
            out = out[: self.max_output_bytes]
            truncated = True
        if len(err) > self.max_output_bytes:
            err = err[: self.max_output_bytes]
            truncated = True
        record = CommandRecord(
            index=0,
            argv=[sanitize(a) for a in argv],
            purpose=purpose,
            returncode=rc,
            stdout=sanitize(out),
            stderr=sanitize(err),
            elapsed_ms=elapsed_ms,
            truncated=truncated,
            stdout_sha256=hashlib.sha256(out.encode("utf-8", errors="replace")).hexdigest(),
        )
        with self._lock:
            record.index = len(self._ledger) + 1
            self._ledger.append(record)
            self._flush_locked()
            callback = self.on_command
        if callback is not None:
            try:
                callback(record.to_dict())
            except Exception:  # noqa: BLE001 — 进度回调失败不影响命令执行
                pass
        return record

    def shell(self, command: list[str] | str, *, purpose: str = "", timeout_seconds: int | None = None) -> CommandRecord:
        """hdc shell：list 形式逐参传递；str 形式作为单个远端命令传递。"""
        remote = [command] if isinstance(command, str) else list(command)
        return self.run(["shell", *remote], purpose=purpose, timeout_seconds=timeout_seconds)

    def file_send(self, local: str | Path, remote: str, *, purpose: str = "") -> CommandRecord:
        return self.run(["file", "send", str(local), remote], purpose=purpose)

    def file_recv(self, remote: str, local: str | Path, *, purpose: str = "") -> CommandRecord:
        return self.run(["file", "recv", remote, str(local)], purpose=purpose)

    # ------------------------------------------------------------------
    def _flush_locked(self) -> None:
        if not self.ledger_path:
            return
        try:
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with self.ledger_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(self._ledger[-1].to_dict(), ensure_ascii=False) + "\n")
        except OSError:
            pass

    def ledger_records(self) -> list[CommandRecord]:
        with self._lock:
            return list(self._ledger)

    def command_count(self) -> int:
        with self._lock:
            return len(self._ledger)
