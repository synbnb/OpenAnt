"""Tests for the opt-in source-locator configuration contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    EndpointCapability,
    OpenGrokConfig,
    ProbeResult,
    SourceLocatorConfigError,
    load_source_locator_config,
    parse_source_locator_config,
)
from utilities.llm import ConfigError, parse_config, serialise_config  # noqa: E402


def _source_locator(**opengrok_overrides):
    opengrok = {
        "base_url": "https://grok.example/source",
        "project": "openharmony",
        "api_prefix": "/api/v1",
        "timeout_seconds": 9,
        "max_retries": 2,
        "max_source_bytes": 16384,
        "max_results": 20,
        "max_hits_per_file": 2,
        "auth": {"mode": "none"},
    }
    opengrok.update(opengrok_overrides)
    return {
        "enabled": True,
        "target_revision": "OpenHarmony-6.1-LTS",
        "opengrok": opengrok,
        "manifest": {"source": "local", "path": "config/openharmony/ohos.xml"},
        "gitcode": {
            "allowed_hosts": ["gitcode.com"],
            "allowed_orgs": ["openharmony"],
            "destination_root": "source_code_base",
        },
    }


def test_absent_section_preserves_scan_only_config():
    assert parse_source_locator_config({}) is None
    config = parse_config({})
    assert config.source_locator is None
    assert "source_locator" not in serialise_config(config)


def test_main_config_round_trip_keeps_typed_source_locator_section():
    config = parse_config({"source_locator": _source_locator()})
    assert config.source_locator is not None
    assert config.source_locator.target_revision == "OpenHarmony-6.1-LTS"
    assert config.source_locator.opengrok is not None
    assert config.source_locator.manifest is not None
    round_trip = serialise_config(config)
    assert round_trip["source_locator"]["opengrok"]["base_url"] == "https://grok.example/source"
    reparsed = parse_config(round_trip)
    assert reparsed.source_locator == config.source_locator


def test_bearer_auth_stores_only_environment_variable_name():
    config = parse_source_locator_config(
        {
            "source_locator": _source_locator(
                auth={"mode": "bearer_env", "token_env": "OPENANT_GROK_TOKEN"}
            )
        }
    )
    assert config is not None and config.opengrok is not None
    assert config.opengrok.auth.resolve_token({"OPENANT_GROK_TOKEN": " secret "}) == "secret"
    serialized = json.dumps(config.to_dict(), ensure_ascii=False)
    assert "secret" not in serialized
    assert "OPENANT_GROK_TOKEN" in serialized


def test_client_receives_environment_token_without_leaking_it_to_config():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request):
        seen.append(request)
        return httpx.Response(
            200,
            json={"time": 1, "resultCount": 0, "startDocument": 0, "endDocument": -1, "results": {}},
            request=request,
        )

    raw = _source_locator(auth={"mode": "bearer_env", "token_env": "OPENANT_GROK_TOKEN"})
    config = parse_source_locator_config({"source_locator": raw})
    assert config is not None and config.opengrok is not None
    with config.opengrok.build_client(
        environ={"OPENANT_GROK_TOKEN": "secret-token"},
        transport=httpx.MockTransport(handler),
    ) as client:
        client.search(full="paramservice")
    assert seen[0].headers["authorization"] == "Bearer secret-token"
    assert "secret-token" not in json.dumps(config.to_dict())


def test_probe_result_can_be_attached_and_round_tripped():
    config = OpenGrokConfig.from_mapping(_source_locator()["opengrok"])
    probe = ProbeResult(
        base_url=config.base_url,
        api_prefix=config.api_prefix,
        reachable=True,
        version="OpenGrok 1.14.11",
        index_time="2026-04-09T10:21:31.737+00:00",
        capabilities={
            "search": EndpointCapability(name="search", available=True, status_code=200),
            "file_content": EndpointCapability(
                name="file_content", available=False, status_code=401, requires_auth=True
            ),
        },
        warnings=("file/content 需要认证",),
    )
    with_probe = config.with_probe(probe)
    assert with_probe.last_probe == probe
    reparsed = OpenGrokConfig.from_mapping(with_probe.to_dict())
    assert reparsed.last_probe == probe
    assert reparsed.last_probe.capabilities["file_content"].requires_auth is True


@pytest.mark.parametrize(
    ("section", "message"),
    [
        ({"source_locator": {"opengrok": {"project": "openharmony"}}}, "base_url"),
        ({"source_locator": {"opengrok": {"base_url": "http://grok.example/source"}}}, "HTTPS"),
        (
            {"source_locator": _source_locator(api_prefix="/api/../v1")},
            "api_prefix",
        ),
        (
            {"source_locator": _source_locator(auth={"mode": "bearer_env"})},
            "token_env",
        ),
        ({"source_locator": {"target_revision": "../../main"}}, "revision"),
    ],
)
def test_invalid_source_locator_values_fail_closed(section, message):
    with pytest.raises(SourceLocatorConfigError, match=message):
        parse_source_locator_config(section)


def test_invalid_source_locator_is_reported_as_config_error_by_llm_loader():
    with pytest.raises(ConfigError, match="source_locator"):
        parse_config({"source_locator": {"enabled": True}})


def test_required_loader_distinguishes_missing_file_and_missing_section(tmp_path):
    missing = tmp_path / "missing.json"
    assert load_source_locator_config(missing) is None
    with pytest.raises(SourceLocatorConfigError, match="不存在"):
        load_source_locator_config(missing, required=True)

    plain = tmp_path / "plain.json"
    plain.write_text("{}", encoding="utf-8")
    with pytest.raises(SourceLocatorConfigError, match="未设置 source_locator"):
        load_source_locator_config(plain, required=True)


def test_disabled_section_may_be_explicitly_empty_but_require_rejects_use():
    config = parse_source_locator_config({"source_locator": {"enabled": False}})
    assert config is not None
    assert config.enabled is False
    with pytest.raises(SourceLocatorConfigError, match="已禁用"):
        config.require_opengrok()
