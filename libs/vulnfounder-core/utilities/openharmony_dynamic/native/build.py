"""native/unix_client.c 交叉编译与推送（R4）。

工具链：commandline-tools 内置 llvm（armv7-unknown-linux-ohos-clang），
与板端 ABI（32-bit ARM）一致。产物 SHA-256 入台账。
"""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from ..transports.base import TransportError

if TYPE_CHECKING:
    from ..hdc_client import HDCClient

_C_SOURCE = Path(__file__).with_name("unix_client.c")
_TOOLCHAIN_ROOT = (
    Path(__file__).resolve().parents[2] / "dynamic_tester" / "toolchains" /
    "commandline-tools-mac-arm64-6.1.0.860" / "command-line-tools"
)
_CLANG = _TOOLCHAIN_ROOT / "sdk/default/openharmony/native/llvm/bin/aarch64-unknown-linux-ohos-clang"
_SYSROOT = _TOOLCHAIN_ROOT / "sdk/default/openharmony/native/sysroot"

DEVICE_DIR = "/data/local/tmp/vf"


def build_unix_client(force: bool = False) -> Path:
    """交叉编译通用 unix 客户端，返回本地产物路径（缓存按源码哈希）。"""
    if not _CLANG.exists():
        raise TransportError(f"交叉编译器不存在: {_CLANG}")
    src_hash = hashlib.sha256(_C_SOURCE.read_bytes()).hexdigest()[:12]
    out = Path(tempfile.gettempdir()) / f"vf_unix_client_{src_hash}"
    if out.exists() and not force:
        return out
    cmd = [
        str(_CLANG),
        f"--sysroot={_SYSROOT}",
        "-O2", "-static", "-Wall",
        "-o", str(out),
        str(_C_SOURCE),
    ]
    completed = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False, timeout=120, check=False)
    if completed.returncode != 0:
        raise TransportError(
            "unix_client.c 交叉编译失败:\n"
            + completed.stderr.decode("utf-8", errors="replace")[-2000:]
        )
    return out


def push_unix_client(hdc: "HDCClient", binary: Path | None = None) -> str:
    """推送客户端到设备固定路径，返回设备侧路径。"""
    local = binary or build_unix_client()
    remote = f"{DEVICE_DIR}/unix_client"
    hdc.run(["shell", "mkdir", "-p", DEVICE_DIR], purpose="mkdir:vf")
    hdc.file_send(local, remote, purpose="push:unix_client")
    rec = hdc.run(["shell", "chmod", "755", remote], purpose="chmod:unix_client")
    if rec.returncode != 0:
        raise TransportError(f"chmod unix_client 失败: {rec.stderr}")
    sha = hashlib.sha256(local.read_bytes()).hexdigest()
    return remote


def compile_and_push(hdc: "HDCClient", *, force: bool = False) -> tuple[str, str]:
    """编译并推送；返回 (device_path, sha256)。"""
    local = build_unix_client(force=force)
    device_path = push_unix_client(hdc, local)
    return device_path, hashlib.sha256(local.read_bytes()).hexdigest()
