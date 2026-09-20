"""Data models for dynamic testing results."""

from dataclasses import dataclass, field
from typing import Any


# Valid test result statuses
# SKIPPED: the finding was never executed — its language has no Docker
# template. Distinct from ERROR (a test ran and failed) so it does not
# inflate the error count or trigger retries.
VALID_STATUSES = {"CONFIRMED", "NOT_REPRODUCED", "BLOCKED", "INCONCLUSIVE", "ERROR", "SKIPPED"}


@dataclass
class TestEvidence:
    """A single piece of evidence from a dynamic test."""
    type: str       # "file_read", "http_response", "command_output", "network_capture"
    content: str

    def to_dict(self) -> dict:
        return {"type": self.type, "content": self.content}


@dataclass
class DynamicTestResult:
    """Result from dynamically testing a single finding."""
    finding_id: str
    status: str         # CONFIRMED, NOT_REPRODUCED, BLOCKED, INCONCLUSIVE, ERROR, SKIPPED
    details: str
    evidence: list[TestEvidence] = field(default_factory=list)
    test_code: str = ""       # Generated test script (for reproducibility)
    dockerfile: str = ""      # Generated Dockerfile
    docker_compose: str = ""  # Generated docker-compose.yml (if multi-service)
    elapsed_seconds: float = 0.0
    generation_cost_usd: float = 0.0
    generation_input_tokens: int = 0
    generation_output_tokens: int = 0
    retry_count: int = 0
    # OpenHarmony 真机模式生成的可复查 PoC/Exp 产物。Docker/Claude Code
    # 仍可保持默认空字典，因而不改变既有调用方的字段语义。
    artifacts: dict[str, str] = field(default_factory=dict)
    # OpenHarmony 真机模式的结构化证据摘要。它与 ``artifacts`` 并存：
    # ``artifacts`` 保持历史的字符串值兼容，``observation`` 让前端和
    # 审计工具无需解析 ``carrier.*`` 字符串即可区分“服务路径已达”、
    # “危险参数受输入影响”和“安全影响已确认”。Docker/Claude Code
    # 结果默认为空，不改变旧调用方的状态语义。
    observation: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "status": self.status,
            "details": self.details,
            "evidence": [e.to_dict() for e in self.evidence],
            "test_code": self.test_code,
            "dockerfile": self.dockerfile,
            "docker_compose": self.docker_compose,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "generation_cost_usd": round(self.generation_cost_usd, 6),
            "generation_input_tokens": self.generation_input_tokens,
            "generation_output_tokens": self.generation_output_tokens,
            "retry_count": self.retry_count,
            "artifacts": dict(self.artifacts),
            "observation": dict(self.observation),
        }
