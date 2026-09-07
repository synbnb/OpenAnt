from __future__ import annotations

import json
import sys
from pathlib import Path

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

import pytest  # noqa: E402

from core.source_locator import (  # noqa: E402
    CandidateReviewError,
    LLMCandidateReviewer,
    build_candidate_review_prompt,
)


def _candidates() -> tuple[dict[str, object], ...]:
    return (
        {
            "project_name": "developtools_smartperf_host",
            "source_root": "developtools/smartperf_host",
            "source_path": "/openharmony/developtools/smartperf_host/sp_server_socket.cpp",
            "repo_url": "https://gitcode.com/openharmony/developtools_smartperf_host",
            "ranking_score": 9681,
            "role_evidence_counts": {"socket_accept_read": 8, "client_send": 9},
            "evidence_ids": ["E-smart-server", "E-smart-client"],
            "source_facts": ["sp_server_socket.cpp: recvfrom(fd, buf, len, 0, ...)"],
        },
        {
            "project_name": "developtools_profiler",
            "source_root": "developtools/profiler",
            "source_path": "/openharmony/developtools/profiler/host/smartperf/client/client_command/sp_server_socket.cpp",
            "repo_url": "https://gitcode.com/openharmony/developtools_profiler",
            "ranking_score": 1543,
            "role_evidence_counts": {"socket_accept_read": 8, "client_send": 9},
            "evidence_ids": ["E-prof-server", "E-prof-build"],
            "source_facts": ["BUILD.gn: ohos_executable(\"SP_daemon\")"],
        },
    )


def test_prompt_contains_pk_factors_and_only_candidate_data() -> None:
    prompt = build_candidate_review_prompt(
        target={"process_hint": "SP_daemon", "transport": "UDP", "port": 8283},
        candidates=_candidates(),
    )
    payload = json.loads(prompt)
    assert payload["target"]["process_hint"] == "SP_daemon"
    assert payload["rules"]["process_build_ownership_matters"] is True
    assert payload["rules"]["duplicate_or_split_source_must_be_explicit"] is True
    assert {item["project_name"] for item in payload["candidates"]} == {
        "developtools_smartperf_host",
        "developtools_profiler",
    }


def test_reviewer_accepts_only_a_supplied_repository_and_evidence() -> None:
    def model(_prompt: str):
        return {
            "primary_repository": "developtools_profiler",
            "primary_role": "process_owner",
            "confidence": "high",
            "reason": "构建目标直接声明 SP_daemon，另一候选更像拆分副本",
            "evidence_ids": ["E-prof-build"],
            "related_repositories": [
                {
                    "project_name": "developtools_smartperf_host",
                    "role": "duplicate_or_split_source",
                    "evidence_ids": ["E-smart-server"],
                }
            ],
        }

    result = LLMCandidateReviewer(model_call=model).review(
        target={"process_hint": "SP_daemon"},
        candidates=_candidates(),
    )
    assert result.primary_repository == "developtools_profiler"
    assert result.primary_role == "process_owner"
    assert result.related_repositories[0]["role"] == "duplicate_or_split_source"


def test_reviewer_normalizes_unknown_related_role_without_dropping_primary() -> None:
    def model(_prompt: str):
        return {
            "primary_repository": "developtools_profiler",
            "primary_role": "server_implementation",
            "confidence": "medium",
            "reason": "候选源码和构建目标均已提供",
            "evidence_ids": ["E-prof-build"],
            "related_repositories": [
                {
                    "project_name": "developtools_smartperf_host",
                    "role": "设备侧镜像或客户端副本",
                    "evidence_ids": ["E-smart-server"],
                }
            ],
        }

    result = LLMCandidateReviewer(model_call=model).review(
        target={"process_hint": "SP_daemon"},
        candidates=_candidates(),
    )
    assert result.primary_repository == "developtools_profiler"
    assert result.primary_role == "server_implementation"
    assert result.related_repositories[0]["role"] == "unknown"


def test_reviewer_rejects_unknown_repository_or_evidence() -> None:
    def model(_prompt: str):
        return {
            "primary_repository": "not_in_candidates",
            "primary_role": "server_implementation",
            "confidence": "high",
            "reason": "猜测",
            "evidence_ids": ["E-not-provided"],
            "related_repositories": [],
        }

    with pytest.raises(CandidateReviewError):
        LLMCandidateReviewer(model_call=model).review(
            target={"process_hint": "SP_daemon"},
            candidates=_candidates(),
        )
