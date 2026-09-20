"""通用协议编码器。

契约：编码器是纯函数 `encode(descriptor, field_values) → bytes`；长度字段
（总长、参数个数、串长）由编码器自算。任何 case-sensitive 键通过
`raw_key_overrides` 通道做等长、唯一命中、tag 校验的字节回补（§9.9）。
"""

from __future__ import annotations

import re
import struct
import json
from typing import Any

from ..models import ProtocolDescriptor

_SAFE_KEY_RE = re.compile(r"[A-Za-z0-9_.]{1,128}")
_SAFE_DOMAIN_RE = re.compile(r"[A-Za-z0-9_.-]{1,16}")
_SAFE_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")


class CodecError(ValueError):
    """编码期错误：长度越界、键非法、值类型不支持。禁止产生残缺产物。"""


# ---------------------------------------------------------------------------
# hisysevent EventRaw
# ---------------------------------------------------------------------------

def _encode_event_raw_varint(value: int, encode_type: int) -> bytes:
    """OpenHarmony EventRaw 的 tag 变长整数。

    首字节 = (encode_type << 6) | (0x20 若 value >= 0x20) | (value & 0x1F)，
    其后为 7-bit 续字节。与 dynamic_tester/openharmony_device.py 的既有实现
    保持字节级一致（该实现已在真机验证）。
    """
    if value < 0:
        raise CodecError("EventRaw varint 不能编码负数")
    first = (int(encode_type) << 6) | (0x20 if value >= 0x20 else 0) | (value & 0x1F)
    result = bytearray([first])
    value >>= 5
    while value:
        result.append((0x80 if value >= 0x80 else 0) | (value & 0x7F))
        value >>= 7
    return bytes(result)


_VALUE_TYPES = {"bool": 1, "int64": 8, "double": 11, "string": 12}


def _encode_event_raw_param(key: str, value: Any) -> bytes:
    key_bytes = key.encode("utf-8")
    encoded = bytearray(_encode_event_raw_varint(len(key_bytes), 1))
    encoded.extend(key_bytes)
    if isinstance(value, bool):
        encoded.append(1 << 1)
        signed = 1 if value else 0
        encoded.extend(_encode_event_raw_varint(signed, 0))
    elif isinstance(value, int) and not isinstance(value, bool):
        if not -(1 << 63) <= value < (1 << 63):
            raise CodecError(f"int64 越界: {key}")
        encoded.append(8 << 1)
        unsigned = (value << 1) if value >= 0 else ((-value << 1) - 1)
        encoded.extend(_encode_event_raw_varint(unsigned, 0))
    elif isinstance(value, float):
        encoded.append(11 << 1)
        encoded.extend(_encode_event_raw_varint(8, 1))
        encoded.extend(struct.pack("<d", float(value)))
    elif isinstance(value, str):
        if len(value) > 4096:
            raise CodecError(f"字符串超长: {key}")
        encoded.append(12 << 1)
        value_bytes = value.encode("utf-8")
        encoded.extend(_encode_event_raw_varint(len(value_bytes), 1))
        encoded.extend(value_bytes)
    else:
        raise CodecError(f"不支持的参数类型: {key}={value!r}")
    return bytes(encoded)


def encode_hisysevent_eventraw(
    field_values: dict[str, Any],
    *,
    descriptor: ProtocolDescriptor | None = None,
) -> bytes:
    """构造一条 hisysevent EventRaw 数据报。

    必填域：domain / stringid。type 缺省为 1（FAULT 型，NO_DRAW 实测用 1）。
    时间戳缺省为构造时刻。uid/pid 置 0，由设备侧 on_send_transform
    （patch_event_credentials）回填——服务端校验 header.uid == SCM uid。
    """
    domain = str(field_values.get("domain") or "")
    name = str(field_values.get("stringid") or field_values.get("name") or "")
    if not _SAFE_DOMAIN_RE.fullmatch(domain):
        raise CodecError(f"domain 不安全: {domain!r}")
    if not _SAFE_NAME_RE.fullmatch(name):
        raise CodecError(f"stringid 不安全: {name!r}")
    try:
        event_type = int(field_values.get("type") or 1)
    except (TypeError, ValueError) as exc:
        raise CodecError("type 必须是 1..4 的整数") from exc
    if not 1 <= event_type <= 4:
        raise CodecError("type 必须是 1..4 的整数")

    timestamp = int(field_values.get("timestamp") or 0) or int(_now_ms())
    tid = int(field_values.get("tid") or 0)

    header = bytearray(80)
    header[0:17] = domain.encode("utf-8")[:16].ljust(17, b"\0")
    header[17:50] = name.encode("utf-8")[:32].ljust(33, b"\0")
    struct.pack_into("<Q", header, 50, timestamp)
    header[58] = int(field_values.get("timezone") or 0)
    # uid@59 / pid@63 占位为 0；设备侧 helper 回填真实凭证
    struct.pack_into("<I", header, 59, 0)
    struct.pack_into("<I", header, 63, 0)
    struct.pack_into("<I", header, 67, tid)
    struct.pack_into("<Q", header, 71, 0)
    header[79] = (event_type - 1) & 0x03

    params: list[tuple[str, Any]] = []
    reserved = {"domain", "stringid", "name", "type", "timestamp", "timezone", "tid"}
    for key, value in field_values.items():
        if key in reserved:
            continue
        if not isinstance(key, str) or not _SAFE_KEY_RE.fullmatch(key):
            raise CodecError(f"参数键不安全: {key!r}")
        params.append((key, value))
    if not params:
        raise CodecError("EventRaw 至少需要一个业务参数")

    encoded = bytearray(struct.pack("<i", 0))
    encoded.extend(header)
    encoded.extend(struct.pack("<i", len(params)))
    for key, value in params:
        encoded.extend(_encode_event_raw_param(key, value))
    struct.pack_into("<i", encoded, 0, len(encoded))
    if not 85 <= len(encoded) <= 384 * 1024:
        raise CodecError(f"EventRaw 长度越界: {len(encoded)}")
    return _apply_raw_key_overrides(bytes(encoded), field_values, descriptor)


def _apply_raw_key_overrides(
    blob: bytes,
    field_values: dict[str, Any],
    descriptor: ProtocolDescriptor | None,
) -> bytes:
    """按描述符的 case_sensitive 键做等长字节回补（§9.9）。

    覆盖场景：调用方或上游 schema 把 case-sensitive 键（如 `info_`）以大写形态
    （`INFO_`）传入。编码器在产物中检索与目标键等长的大写变体，命中点必须：
    (a) 唯一；(b) 前一字节是 keylen tag（(1<<6)|len）；(c) 后一字节是值类型
    字节。若大写变体只出现在其它键/值的内部（如 FREEZE_INFO_PATH 内含
    INFO_ 子串），则不满足 (b)/(c)，视为无需回补，跳过而不报错。
    """
    if descriptor is None:
        return blob
    overrides = [f for f in descriptor.fields if f.case_sensitive]
    if not overrides:
        return blob
    out = blob
    for spec in overrides:
        name = spec.name
        upper = name.upper()
        if upper == name:
            continue
        if name.encode() in out:
            # 键已按精确大小写存在，无需回补
            continue
        positions: list[int] = []
        start = 0
        while True:
            idx = out.find(upper.encode(), start)
            if idx < 0:
                break
            positions.append(idx)
            start = idx + 1
        for idx in positions:
            prev_byte = out[idx - 1] if idx else 0
            keylen_tag = prev_byte & 0x1F
            if (prev_byte >> 6) != 1 or keylen_tag != len(name):
                continue  # 大写子串命中在其它内容内部，不是键起点
            out = out[:idx] + name.encode() + out[idx + len(name):]
            break
        else:
            if positions:
                # 存在大写变体但都不满足 tag 校验：键本身未出现，属正常
                continue
    return out


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# sp_daemon 文本协议（key::value）
# ---------------------------------------------------------------------------

def encode_sp_daemon_text(frame_values: dict[str, Any]) -> bytes:
    """一帧 `key::value` 文本。value 原样传递（污点由漏洞本身承载）。"""
    parts: list[str] = []
    for key, value in frame_values.items():
        key = str(key)
        if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", key):
            raise CodecError(f"sp_daemon 帧键不安全: {key!r}")
        parts.append(f"{key}::{value}")
    if not parts:
        raise CodecError("sp_daemon 空帧")
    text = "\n".join(parts) + "\n" if len(parts) > 1 else parts[0]
    return text.encode("utf-8")


def encode_generic_descriptor(
    descriptor: ProtocolDescriptor, field_values: dict[str, Any],
) -> bytes:
    """按自动发现描述符的 wire_format 编码，不依赖协议族名称。

    该编码器只处理可由源码描述清楚的通用线路形态；未知/自定义二进制布局
    仍然返回 CodecError，由契约编译阶段保留为待复核，而不是猜一个报文。
    """
    kind = descriptor.encoder_kind
    fmt = descriptor.wire_format or {}
    if kind == "raw_text":
        value = field_values.get("payload", field_values.get("raw", ""))
        if not isinstance(value, (str, bytes)):
            raise CodecError("raw_text 的 payload 必须是字符串或字节串")
        return value if isinstance(value, bytes) else value.encode("utf-8")
    if kind == "json":
        body = {k: v for k, v in field_values.items()
                if k not in {"mode", "host", "port", "target", "local_path", "marker"}}
        return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if kind == "key_value":
        pair_separator = str(fmt.get("pair_separator", "::"))
        record_separator = str(fmt.get("record_separator", "\n"))
        terminator = str(fmt.get("terminator", ""))
        if not pair_separator or len(pair_separator) > 16 or len(record_separator) > 16:
            raise CodecError("key_value 分隔符不合法")
        ordered: list[tuple[str, Any]] = []
        declared = sorted(descriptor.fields, key=lambda f: f.order)
        declared_names = {f.name for f in declared}
        for spec in declared:
            if spec.name in field_values:
                ordered.append((spec.name, field_values[spec.name]))
        for key, value in field_values.items():
            if key in declared_names or key in {"mode", "host", "port", "target", "local_path", "marker"}:
                continue
            ordered.append((str(key), value))
        if not ordered:
            raise CodecError("key_value 没有可编码字段")
        for key, _ in ordered:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", key):
                raise CodecError(f"key_value 键不安全: {key!r}")
        return (record_separator.join(f"{k}{pair_separator}{v}" for k, v in ordered)
                + terminator).encode("utf-8")
    raise CodecError(f"自动描述符没有可用编码器: {descriptor.descriptor_id}/{kind}")


_ENCODERS = {
    "hisysevent_eventraw": encode_hisysevent_eventraw,
    "sp_daemon_text": encode_sp_daemon_text,
}


def encode(descriptor: ProtocolDescriptor, field_values: dict[str, Any]) -> bytes:
    encoder = _ENCODERS.get(descriptor.descriptor_id)
    if encoder is None:
        return encode_generic_descriptor(descriptor, field_values)
    if descriptor.descriptor_id == "hisysevent_eventraw":
        return encode_hisysevent_eventraw(field_values, descriptor=descriptor)
    return encoder(field_values)
