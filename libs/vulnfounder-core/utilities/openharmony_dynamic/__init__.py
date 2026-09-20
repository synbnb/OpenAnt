"""OpenHarmony 真机动态测试框架 v2。

分层（docs/VULNFOUNDER_DYNAMIC_TEST_REWRITE_PLAN.zh-CN.md §4.1）：
- models        数据模型（contract / descriptor / observation / verdict）
- hdc_client    统一 HDC 调用层
- protocols     协议描述符 + 通用编码器
- transports    传输层（hap / native_unix / cli）
- native        原生客户端源码与交叉编译
- observation   快照与预言机
- verdict       判定引擎
- runner        状态机编排
"""

from .hdc_client import CommandRecord, HDCClient, HDCError, sanitize
from .models import (
    ArtifactForm,
    Contract,
    Observation,
    OracleResult,
    OracleSpec,
    ProtocolSpec,
    SyscallRecord,
    Verdict,
    new_run_id,
)
from .protocols import (
    CodecError,
    HISYSEVENT_EVENTRAW,
    SP_DAEMON_TEXT,
    encode,
    encode_hisysevent_eventraw,
    encode_sp_daemon_text,
    get_descriptor,
)

__all__ = [
    "CommandRecord",
    "HDCClient",
    "HDCError",
    "sanitize",
    "ArtifactForm",
    "Contract",
    "Observation",
    "OracleResult",
    "OracleSpec",
    "ProtocolSpec",
    "SyscallRecord",
    "Verdict",
    "new_run_id",
    "CodecError",
    "HISYSEVENT_EVENTRAW",
    "SP_DAEMON_TEXT",
    "encode",
    "encode_hisysevent_eventraw",
    "encode_sp_daemon_text",
    "get_descriptor",
]
