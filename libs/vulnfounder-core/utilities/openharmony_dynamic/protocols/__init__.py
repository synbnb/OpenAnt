"""协议层：描述符注册表 + 通用编码器。"""

from .codec import CodecError, encode, encode_hisysevent_eventraw, encode_sp_daemon_text
from .descriptors import (
    HISYSEVENT_EVENTRAW,
    SP_DAEMON_TEXT,
    get_descriptor,
    register,
)

__all__ = [
    "CodecError",
    "encode",
    "encode_hisysevent_eventraw",
    "encode_sp_daemon_text",
    "HISYSEVENT_EVENTRAW",
    "SP_DAEMON_TEXT",
    "get_descriptor",
    "register",
]
