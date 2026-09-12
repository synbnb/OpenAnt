"""入口函数语义复核器的证据边界测试。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    LLMEntrypointAttributionError,
    LLMEntrypointAttributor,
    build_entrypoint_attribution_prompt,
)


def _candidates() -> list[dict]:
    return [
        {
            "candidate_id": "EP-C-recv1",
            "function": "SpThreadSocket::HandleMsg",
            "source_path": "/openharmony/base/profiler/sp_thread_socket.cpp",
            "line_start": 380,
            "line_end": 430,
            "entry_kinds": ["socket_accept_read"],
            "anchor_lines": [395],
            "evidence_ids": ["E-recv1"],
            "source": "void HandleMsg() { recvfrom(fd, buf, size, 0, nullptr, nullptr); HandleCommand(buf); }",
        },
        {
            "candidate_id": "EP-C-setup1",
            "function": "SpThreadSocket::Init",
            "source_path": "/openharmony/base/profiler/sp_thread_socket.cpp",
            "line_start": 100,
            "line_end": 130,
            "entry_kinds": ["socket_server_registration"],
            "anchor_lines": [112],
            "evidence_ids": ["E-setup1"],
            "source": "void Init() { bind(fd, address); listen(fd, 8); }",
        },
    ]


def test_prompt_is_bounded_and_marks_source_as_untrusted_data():
    payload = json.loads(
        build_entrypoint_attribution_prompt(
            target={"socket_path": "/dev/unix/socket/profiler"},
            candidates=_candidates(),
        )
    )
    assert payload["rules"]["candidate_only"] is True
    assert payload["rules"]["accepted_requires_high_confidence"] is True
    assert payload["candidates"][0]["candidate_id"] == "EP-C-recv1"


def test_model_decisions_are_limited_to_candidates_and_evidence():
    rows = _candidates()

    def model(prompt: str):
        del prompt
        return {
            "decisions": [
                {
                    "candidate_id": "EP-C-recv1",
                    "role": "inbound_receive",
                    "status": "accepted",
                    "confidence": "high",
                    "evidence_ids": ["E-recv1"],
                    "reason": "函数直接从 socket 接收数据并进入消息处理",
                },
                {
                    "candidate_id": "EP-C-setup1",
                    "role": "setup_only",
                    "status": "rejected",
                    "confidence": "high",
                    "evidence_ids": ["E-setup1"],
                    "reason": "仅负责 bind/listen，不消费外部消息",
                },
            ]
        }

    result = LLMEntrypointAttributor(model_call=model).attribute(target=None, candidates=rows)
    assert result.accepted_candidate_ids == ("EP-C-recv1",)
    assert result.decisions[1].eligible is False
    assert result.to_dict()["decision_count"] == 2


def test_omitted_candidate_is_explicitly_unresolved():
    def model(prompt: str):
        del prompt
        return {"decisions": []}

    result = LLMEntrypointAttributor(model_call=model).attribute(target=None, candidates=_candidates())
    assert all(item.status == "unresolved" for item in result.decisions)
    assert not result.accepted_candidate_ids


def test_unknown_candidate_or_evidence_is_rejected():
    def unknown_candidate(prompt: str):
        del prompt
        return {
            "decisions": [
                {
                    "candidate_id": "EP-C-nope",
                    "role": "inbound_receive",
                    "status": "accepted",
                    "confidence": "high",
                    "evidence_ids": ["E-recv1"],
                    "reason": "伪造候选",
                }
            ]
        }

    with pytest.raises(LLMEntrypointAttributionError, match="candidate_id"):
        LLMEntrypointAttributor(model_call=unknown_candidate).attribute(target=None, candidates=_candidates())

    def unknown_evidence(prompt: str):
        del prompt
        return {
            "decisions": [
                {
                    "candidate_id": "EP-C-recv1",
                    "role": "inbound_receive",
                    "status": "accepted",
                    "confidence": "high",
                    "evidence_ids": ["E-other"],
                    "reason": "伪造证据",
                }
            ]
        }

    with pytest.raises(LLMEntrypointAttributionError, match="evidence_id"):
        LLMEntrypointAttributor(model_call=unknown_evidence).attribute(target=None, candidates=_candidates())
