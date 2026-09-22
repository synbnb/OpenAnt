"""Stage1/2 finding → 契约编译器输入适配层（自动化方案 §2）。

把 pipeline_output.json / dataset_enhanced.json 的 finding 块规约为
FindingInput 标准结构；也接受手工构造的 finding（回归锚定模式）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FindingInput:
    """契约编译器的标准输入。"""

    finding_id: str              # 如 "DP-02"
    unit_id: str                 # 如 "developtools_profiler_dp02"
    vuln_class: str              # §3.3 映射表的键
    description: str = ""        # finding 的一句话结论
    source_paths: list[str] = field(default_factory=list)   # 相关源码文件
    evidence_lines: list[list[int]] = field(default_factory=list)  # 与 source_paths 对齐的 [起行, 止行]
    sink: str = ""               # sink 点描述
    entry_hints: list[str] = field(default_factory=list)    # 静态分析推断的入口线索（可为空）
    # 与完整攻击链并列的候选路径。候选路径只作为动态侦查的补充线索，
    # 不代表已经确认的执行路径，也不能覆盖完整攻击链。
    candidate_attack_chains: list[list[str]] = field(default_factory=list)
    repo_root: str = ""          # 源码仓库根（LLM 与校验器读取源码用）
    # Stage 1 原始上下文的有限副本。它不参与契约字段推导，只供入口发现 loop
    # 定位源码、理解调用链和区分入口/内部转发使用。
    analysis_context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "unit_id": self.unit_id,
            "vuln_class": self.vuln_class,
            "description": self.description,
            "source_paths": list(self.source_paths),
            "evidence_lines": [list(e) for e in self.evidence_lines],
            "sink": self.sink,
            "entry_hints": list(self.entry_hints),
            "candidate_attack_chains": [list(path) for path in self.candidate_attack_chains],
            "repo_root": self.repo_root,
            "analysis_context": dict(self.analysis_context),
        }

    def to_prompt_dict(self) -> dict[str, Any]:
        """Return the bounded structural view used by dynamic LLM agents.

        Stage 1 findings often contain a long ``reasoning``/``attack_scenario``
        narrative, including shell syntax or exploit strings.  That material is
        useful in the audit artifact, but it is not required to recover a
        server protocol and can trigger an upstream safety filter before the
        model gets to inspect the current source.  Dynamic agents instead need
        the stable identity, sink, source ranges, candidate routes and a small
        allow-list of evidence metadata.  The full finding remains available
        to deterministic persistence and later Stage 2 analysis via
        :meth:`to_dict`.
        """
        context = self.analysis_context if isinstance(self.analysis_context, dict) else {}
        safe_context: dict[str, Any] = {}
        for key in (
            "source_evidence",
            "missing_evidence",
            "candidate_entry_path_ids",
            "entry_path_ids",
            "top_level_entry",
            "status",
            "graph_status",
            "source_revision",
            "reference_revision",
            "候选攻击链",
        ):
            if key in context:
                safe_context[key] = context[key]
        stage_finding = context.get("stage1_finding")
        if isinstance(stage_finding, dict):
            # Keep location/category/evidence, omit prose fields that may carry
            # a pre-written exploit recipe or shell payload.
            safe_context["stage1_finding"] = {
                key: stage_finding[key]
                for key in (
                    "function_analyzed",
                    "file",
                    "line_start",
                    "line_end",
                    "vulnerability_categories",
                    "evidence",
                    "missing_evidence",
                )
                if key in stage_finding
            }
        return {
            "finding_id": self.finding_id,
            "unit_id": self.unit_id,
            "vuln_class": self.vuln_class,
            "source_paths": list(self.source_paths),
            "evidence_lines": [list(e) for e in self.evidence_lines],
            "sink": self.sink,
            "entry_hints": list(self.entry_hints),
            "candidate_attack_chains": [list(path) for path in self.candidate_attack_chains],
            "analysis_context": safe_context,
        }


def finding_from_dict(raw: dict[str, Any]) -> FindingInput:
    return FindingInput(
        finding_id=str(raw["finding_id"]),
        unit_id=str(raw.get("unit_id", "")),
        vuln_class=str(raw.get("vuln_class", "")),
        description=str(raw.get("description", "")),
        source_paths=list(raw.get("source_paths", [])),
        evidence_lines=[list(e) for e in raw.get("evidence_lines", [])],
        sink=str(raw.get("sink", "")),
        entry_hints=list(raw.get("entry_hints", [])),
        candidate_attack_chains=[
            [str(node) for node in path]
            for path in (raw.get("candidate_attack_chains") or [])
            if isinstance(path, (list, tuple))
        ],
        repo_root=str(raw.get("repo_root", "")),
        analysis_context=dict(raw.get("analysis_context") or {}),
    )


def load_finding(path: str | Path) -> FindingInput:
    """从 JSON 文件载入 finding。"""
    return finding_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
