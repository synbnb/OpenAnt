"""agent 层：试跑-修正闭环（自动化方案 §5）。

refine_loop  包裹 Runner 的主循环：跑 → 分类 → 诊断 → LLM 修订 → 重校验 → 再跑
diagnosis    RunRecord → 结构化诊断证据包
budget       预算门（修订/发送/命令/墙钟）
"""

from .budget import Budget
from .diagnosis import Diagnosis, build_diagnosis
from .entry_discovery_loop import EntryCandidate, EntryDiscoveryResult, run_entry_discovery_loop
from .refine_loop import RefineOutcome, classify, refine_loop, revise_contract

__all__ = [
    "Budget",
    "Diagnosis",
    "RefineOutcome",
    "build_diagnosis",
    "EntryCandidate",
    "EntryDiscoveryResult",
    "run_entry_discovery_loop",
    "classify",
    "refine_loop",
    "revise_contract",
]
