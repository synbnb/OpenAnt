"""协议描述符注册表。

描述符按协议族声明（§5.2），每个描述符带源码证据、known_guards、
on_send_transforms 与 raw_key_overrides。禁止按样本写描述符。
"""

from __future__ import annotations

from ..models import FieldSpec, Guard, ProtocolDescriptor, SendTransform

HISYSEVENT_EVENTRAW = ProtocolDescriptor(
    descriptor_id="hisysevent_eventraw",
    endianness="host",
    framing="single_message",
    transports=["unix_dgram"],
    structure_evidence=(
        "base/event_raw: int32 总长 + 80B 头 + int32 参数个数 + 参数序列；"
        "真机实测（2026-09-17，OpenHarmony 6.1.0.26）静默丢弃总长为 0 的报文"
    ),
    fields=[
        FieldSpec(name="domain", type="string", order=0, required=True, evidence="头 @0 17B"),
        FieldSpec(name="stringid", type="string", order=1, required=True, evidence="头 @17 33B"),
        FieldSpec(name="type", type="int64", order=2, evidence="头 @79 (event_type-1)&0x03，1..4；codec 消费"),
        FieldSpec(name="timestamp", type="u64", order=3, evidence="头 @50 毫秒"),
        FieldSpec(name="tid", type="u32", order=4, evidence="头 @67"),
        FieldSpec(name="info_", type="string", order=10, case_sensitive=True,
                  evidence="EventStore::EventCol::INFO == \"info_\"；freeze 链 logPath 载体"),
        FieldSpec(name="FREEZE_INFO_PATH", type="string", order=11,
                  evidence="freeze_detector_plugin.cpp:155 params.freezeExtFile"),
        FieldSpec(name="PID", type="int64", order=12, evidence="freeze 事件业务参数"),
        FieldSpec(name="UID", type="int64", order=13, evidence="freeze 事件业务参数"),
        FieldSpec(name="PACKAGE_NAME", type="string", order=14),
        FieldSpec(name="PROCESS_NAME", type="string", order=15),
        FieldSpec(name="MSG", type="string", order=16),
    ],
    known_guards=[
        Guard(
            name="scm_credential_match",
            evidence="plugins/sysevent_source/event_server.cpp IsValidMsg(:186-208)",
            checked_by="header.uid/pid 必须等于 SCM_CREDENTIALS 真实值 → 设备侧回填",
            guard_log_hints=["credential", "IsValidMsg", "invalid uid", "invalid pid"],
        ),
        Guard(
            name="total_length_check",
            evidence="EventRaw DecodedEvent::IsValid",
            checked_by="总长字段为 0 或与报文不符时静默丢弃",
            guard_log_hints=["invalid", "length"],
        ),
        Guard(
            name="freeze_rule_window",
            evidence="/system/etc/hiview/freeze_rules.xml（板上实测）",
            checked_by=(
                "NO_DRAW/SCREEN_ON/SCREEN_OFF/SCREEN_ON_TIMEOUT/SERVICE_TIMEOUT/CONGESTION"
                " 窗口=0 单事件命中；THREAD_BLOCK_6S 需同包 3S 前驱(-14s)"
            ),
        ),
    ],
    on_send_transforms=[
        SendTransform(
            name="patch_event_credentials",
            kind="device_side_credential_patch",
            evidence="native_datagram_sender.c patch_event_credentials()，真机验证有效",
        ),
    ],
)

SP_DAEMON_TEXT = ProtocolDescriptor(
    descriptor_id="sp_daemon_text",
    endianness="ascii",
    framing="frame_sequence",
    transports=["udp", "tcp"],
    structure_evidence=(
        "sp_thread_socket.cpp HandleMsg/HandleNullMsg：`key::value` 文本帧；"
        "真机实测：set_pkgName 与 catch_network_traffic 需两帧（300ms 间隔）"
    ),
    encoder_kind="key_value",
    # ``::`` 是命令字段的 key/value 分隔符；UDP token 采用独立的 ``:::`
    # 后缀（RemoveToken 先移除它，再交给 SplitMsg）。两者不能混为一种
    # 分隔符，否则合法的 command:::token 会被误判为 key:::value。
    wire_format={
        "pair_separator": "::",
        "token_separator": ":::",
        "record_separator": "\n",
        "terminator": "",
    },
    fields=[
        FieldSpec(name="set_pkgName", type="string", order=0, required=True),
        FieldSpec(name="catch_network_traffic", type="string", order=1),
    ],
    known_guards=[
        Guard(
            name="udp_token_check",
            evidence="sp_thread_socket.cpp:290-313",
            checked_by="CheckUdpToken 默认关闭且对 set 前缀特判放行（实机验证）",
            guard_log_hints=["Token mismatch", "CheckUdpToken"],
        ),
    ],
)


_REGISTRY: dict[str, ProtocolDescriptor] = {
    HISYSEVENT_EVENTRAW.descriptor_id: HISYSEVENT_EVENTRAW,
    SP_DAEMON_TEXT.descriptor_id: SP_DAEMON_TEXT,
}


def get_descriptor(descriptor_id: str) -> ProtocolDescriptor:
    descriptor = _REGISTRY.get(descriptor_id)
    if descriptor is None:
        raise KeyError(f"未注册的协议描述符: {descriptor_id}；已注册: {sorted(_REGISTRY)}")
    return descriptor


def register(descriptor: ProtocolDescriptor) -> None:
    """注册描述符。

    手写的内置描述符保持“先注册者优先”，避免运行时探测覆盖稳定协议。
    ``auto_`` 描述符则属于当前编译会话的临时语义事实：同一个稳定身份在
    重试时可能得到更完整的字段或证据，必须允许后一次、已通过校验的结果
    更新前一次结果。这样不会把某一轮模型的残缺快照冻结到本次重试的后续
    阶段，也不会把临时描述符持久化为全局事实。
    """
    if descriptor.descriptor_id.startswith("auto_"):
        _REGISTRY[descriptor.descriptor_id] = descriptor
        return
    _REGISTRY.setdefault(descriptor.descriptor_id, descriptor)
