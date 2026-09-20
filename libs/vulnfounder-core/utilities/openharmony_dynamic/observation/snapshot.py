"""设备观测快照：文件系统 / hilog / 进程状态 / 响应摘录。

采集契约（§9.0）：
- 文件系统：对每个声明路径做 `ls -lZ` + `stat` + `cat`（exfil 预埋面 / create 观测面 / delete 源面）
- hilog：`hilog -x` 一次性全量 dump，再按时间窗/正则过滤（实机验证的采集方式）
- 进程状态：目标 PID 存活 + faultlog 目录增量
一切设备访问经由 HDCClient（参数数组，无 shell 拼接）。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..hdc_client import HDCClient

_LS_STAT_CAT = "ls -lZ {path} 2>&1; stat {path} 2>&1; cat {path} 2>&1"
_HILOG_DUMP = "hilog -x"
_FAULTLOG_LS = "ls -l /data/log/faultlog/faultlogger-*.log 2>&1 | tail -n 32"
_PIDOF = "pidof {name}"


@dataclass
class FileSnapshot:
    path: str
    exists: bool = False
    listing: str = ""
    stat_text: str = ""
    content: str = ""
    content_sha256: str = ""
    size: int = -1

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "listing": self.listing,
            "stat_text": self.stat_text,
            "content": self.content,
            "content_sha256": self.content_sha256,
            "size": self.size,
        }


def _parse_stat_size(stat_text: str) -> int:
    m = re.search(r"Size:\s+(\d+)", stat_text)
    return int(m.group(1)) if m else -1


class SnapshotError(RuntimeError):
    """快照采集失败（设备不可达等）。"""


def snapshot_paths(hdc: "HDCClient", paths: list[str], *, purpose: str = "") -> dict[str, FileSnapshot]:
    """对一组路径做 ls/stat/cat 三合一采集。单条 shell 内多路径逐个执行，互不影响。"""
    out: dict[str, FileSnapshot] = {}
    for path in paths:
        snap = FileSnapshot(path=path)
        rec = hdc.shell(["sh", "-c", _LS_STAT_CAT.format(path=_quote(path))], purpose=purpose or f"snapshot:{path}")
        text = rec.stdout
        # `cat` 输出在 stat 文本之后；ls -lZ 失败时输出形如 `ls: ... No such file`
        snap.listing, rest = _split_section(text, prefix_ls=True)
        snap.stat_text, snap.content = _split_stat_cat(rest)
        snap.exists = "No such file or directory" not in snap.listing and bool(snap.stat_text.strip())
        snap.size = _parse_stat_size(snap.stat_text)
        if snap.exists and snap.content:
            snap.content_sha256 = hashlib.sha256(snap.content.encode("utf-8", errors="replace")).hexdigest()
        out[path] = snap
    return out


def _quote(path: str) -> str:
    if "'" in path or any(c in path for c in "\x00\n;|&$`\\"):
        raise SnapshotError(f"路径不安全: {path!r}")
    return "'" + path + "'"


def _split_section(text: str, *, prefix_ls: bool) -> tuple[str, str]:
    """粗切：stat 输出以 `  File: ` 或 `File: ` 开始。"""
    m = re.search(r"(?m)^.{0,2}File: ", text)
    if not m:
        return text.strip(), ""
    return text[: m.start()].strip(), text[m.start():]


def _split_stat_cat(stat_and_cat: str) -> tuple[str, str]:
    """stat 文本与 cat 内容以首个不属于 stat 字段的行分界（stat 以 `Modify:`/`Change:`/`Birth:` 块结束）。"""
    m = re.search(r"(?m)^(Modify|Change|Birth):[^\n]*\n", stat_and_cat)
    if not m:
        return stat_and_cat.strip(), ""
    end = m.end()
    # stat 块在最后一个 Change/Birth 行后结束
    tail = stat_and_cat[end:]
    lines = stat_and_cat[:end].splitlines(keepends=True)
    stat_lines = list(lines)
    # 追加 stat 块可能存在的后续字段行（Inode/Blocks/IO Block 等）
    for line in tail.splitlines(keepends=True):
        if re.match(r"^\s*(Inode|Blocks|IO Block|regular file|device|Access|Uid|Gid|Access: \(|Uid: \(|Modify:|Change:|Birth:)", line):
            stat_lines.append(line)
        else:
            break
    consumed = sum(len(l) for l in stat_lines)
    return "".join(stat_lines).strip(), stat_and_cat[consumed:]


@dataclass
class ProcessSnapshot:
    target_process: str
    pids: list[str] = field(default_factory=list)
    faultlog_tail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_process": self.target_process,
            "pids": list(self.pids),
            "faultlog_tail": self.faultlog_tail,
        }


def snapshot_process(hdc: "HDCClient", target_process: str, *, purpose: str = "") -> ProcessSnapshot:
    """目标进程 PID + faultlog 索引尾快照。"""
    rec = hdc.shell(["pidof", target_process], purpose=purpose or f"pidof:{target_process}")
    pids = [p for p in rec.stdout.split() if p.strip().isdigit()]
    rec2 = hdc.shell(["sh", "-c", _FAULTLOG_LS], purpose=purpose or "faultlog:index")
    return ProcessSnapshot(target_process=target_process, pids=pids, faultlog_tail=rec2.stdout)


@dataclass
class HilogDump:
    text: str
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {"sha256": self.sha256, "lines": self.text.count("\n") + (1 if self.text else 0)}


def dump_hilog(hdc: "HDCClient", *, purpose: str = "") -> HilogDump:
    """`hilog -x` 一次性全量 dump（实机验证：不要反复 tail，单次 dump 后本地过滤）。"""
    rec = hdc.shell(_HILOG_DUMP, purpose=purpose or "hilog:dump", timeout_seconds=60)
    return HilogDump(text=rec.stdout, sha256=hashlib.sha256(rec.stdout.encode("utf-8", errors="replace")).hexdigest())


# hilog 行格式：`09-17 17:44:42.123  1234  5678 I C02d01/FreezeDetector: message...`
# （level 列可取 I/E/W/D/F，两处以 E 级输出的 SaveFreezeExtInfoToFile 为证）
_HILOG_LINE_RE = re.compile(
    r"^(?P<date>\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+[IWEF]\s+(?P<tag>\S+?)\s*:\s(?P<msg>.*)$"
)


def filter_hilog(
    dump_text: str,
    *,
    tag: str = "",
    pattern: str = "",
    window_seconds: float | None = None,
    anchor_time: tuple[int, int, int] | None = None,
) -> list[dict[str, Any]]:
    """按 tag / 正则 / 时间窗过滤 hilog dump 文本。

    window_seconds + anchor_time=(h, m, s)：仅保留 anchor 之后 window 秒内的行
    （设备时间与主机无关联，锚点必须来自设备侧时间戳）。
    """
    hits: list[dict[str, Any]] = []
    regex = re.compile(pattern) if pattern else None
    min_seconds: float | None = None
    if window_seconds is not None and anchor_time is not None:
        min_seconds = anchor_time[0] * 3600 + anchor_time[1] * 60 + anchor_time[2]
    for line in dump_text.splitlines():
        m = _HILOG_LINE_RE.match(line.strip())
        if not m:
            continue
        if tag and not m.group("tag").startswith(tag):
            continue
        msg = m.group("msg")
        if regex and not regex.search(msg):
            continue
        hit: dict[str, Any] = {
            "date": m.group("date"),
            "time": m.group("time"),
            "pid": m.group("pid"),
            "tag": m.group("tag"),
            "message": msg,
        }
        if min_seconds is not None:
            h, mi, rest = m.group("time").split(":")
            sec = float(rest)
            cur = int(h) * 3600 + int(mi) * 60 + sec
            # 设备时钟跨天/回绕按 24h 环处理
            delta = cur - min_seconds
            if delta < -3600:  # 跨午夜回绕
                delta += 86400
            hit["delta_seconds"] = round(delta, 3)
            if delta < 0 or delta > window_seconds:
                continue
        hits.append(hit)
    return hits


def device_clock(hdc: "HDCClient") -> tuple[int, int, int] | None:
    """读取设备侧当前时间 (h, m, s)，作为 hilog 时间窗锚点。"""
    rec = hdc.shell(["date", "+%H:%M:%S"], purpose="device-clock")
    m = re.match(r"(\d{2}):(\d{2}):(\d{2})", rec.stdout.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))
