"""Tests for evidence-constrained server/client role adjudication."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    EvidenceStore,
    LLMRoleAttributionError,
    LLMRoleAttributor,
    build_role_attribution_prompt,
)


def _store() -> tuple[EvidenceStore, str]:
    store = EvidenceStore()
    evidence = store.add_evidence(
        kind="socket_bind_listen",
        source_path="/openharmony/base/services/socket_server.cpp",
        line_start=42,
        excerpt="bind(fd, address); listen(fd, 8);",
        tool_name="fixture",
        source_mode="fixture",
        relation_from="/dev/unix/socket/example",
        relation_to="SocketServer::Start",
    )
    return store, evidence.evidence_id


def test_prompt_explains_create_socket_is_neutral_and_keeps_non_test_scopes():
    store, _ = _store()
    prompt = build_role_attribution_prompt(target={"socket_path": "/dev/unix/socket/example"}, evidence=store)
    payload = json.loads(prompt)
    assert payload["rules"]["create_socket_alone_is_neutral"] is True
    assert payload["rules"]["test_or_fuzz_paths_are_non_authoritative"] is True
    assert payload["rules"]["kernel_third_party_generated_build_paths_are_not_automatically_excluded"] is True
    assert payload["evidence"][0]["evidence_id"]


def test_model_decision_is_validated_against_supplied_evidence_ids():
    store, evidence_id = _store()

    def model(prompt: str):
        del prompt
        return {
            "server": {
                "status": "confirmed",
                "confidence": "high",
                "subject": "SocketServer::Start",
                "evidence_ids": [evidence_id],
                "reason": "证据显示 bind/listen 由服务初始化完成",
            },
            "client": {
                "status": "unresolved",
                "confidence": "low",
                "subject": "",
                "evidence_ids": [],
                "reason": "没有客户端连接和发送证据",
            },
        }

    result = LLMRoleAttributor(model_call=model).attribute(target=None, evidence=store)
    assert result.server.status == "confirmed"
    assert result.server.evidence_ids == (evidence_id,)
    assert result.client.status == "unresolved"
    assert result.model_calls == 1


def test_model_cannot_cite_test_or_unknown_evidence():
    store, _ = _store()

    def model(prompt: str):
        del prompt
        return {
            "server": {
                "status": "confirmed",
                "confidence": "high",
                "subject": "Fake",
                "evidence_ids": ["E-not-provided"],
                "reason": "不应通过",
            },
            "client": {
                "status": "unresolved",
                "confidence": "low",
                "subject": "",
                "evidence_ids": [],
                "reason": "无",
            },
        }

    with pytest.raises(LLMRoleAttributionError, match="未提供或被排除"):
        LLMRoleAttributor(model_call=model).attribute(target=None, evidence=store)


def test_markdown_json_is_accepted_but_extra_fields_are_rejected():
    store, evidence_id = _store()

    def fenced(prompt: str):
        del prompt
        payload = {
            "server": {"status": "possible", "confidence": "medium", "subject": "S", "evidence_ids": [evidence_id], "reason": "可能"},
            "client": {"status": "unresolved", "confidence": "low", "subject": "", "evidence_ids": [], "reason": "无"},
        }
        return "```json\n" + json.dumps(payload, ensure_ascii=False) + "\n```"

    assert LLMRoleAttributor(model_call=fenced).attribute(target=None, evidence=store).status == "PARTIAL"

    def extra(prompt: str):
        del prompt
        payload = {
            "server": {"status": "possible", "confidence": "medium", "subject": "S", "evidence_ids": [evidence_id], "reason": "可能"},
            "client": {"status": "unresolved", "confidence": "low", "subject": "", "evidence_ids": [], "reason": "无"},
        }
        payload["server"]["thinking"] = "hidden"
        return payload

    with pytest.raises(LLMRoleAttributionError, match="未知字段"):
        LLMRoleAttributor(model_call=extra).attribute(target=None, evidence=store)
