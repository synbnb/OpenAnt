"""Tests for deterministic OpenHarmony target normalization and query planning."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    LocatorQuery,
    TargetNormalizationError,
    build_initial_queries,
    normalize_and_plan,
    normalize_target,
)


def test_full_socket_path_with_chinese_punctuation_is_normalized():
    target = normalize_target("我想分析‘/dev/unix/socket/paramservice’。", target_revision="OpenHarmony-6.1-LTS")
    assert target.target_type == "unix_socket"
    assert target.socket_path == "/dev/unix/socket/paramservice"
    assert target.basename == "paramservice"
    assert target.service_hint == "paramservice"
    assert target.path_components == ("dev", "unix", "socket", "paramservice")
    assert target.target_revision == "OpenHarmony-6.1-LTS"
    assert json.loads(json.dumps(target.to_dict(), ensure_ascii=False))["schema_version"].endswith("target.v1")


def test_macro_assignment_keeps_macro_hint_and_socket_value():
    target = normalize_target('配置中的 PIPE_NAME = "/dev/unix/socket/paramservice"')
    assert target.target_type == "unix_socket"
    assert target.macro_hint == "PIPE_NAME"
    assert target.socket_path == "/dev/unix/socket/paramservice"
    assert any("PIPE_NAME" in note for note in target.normalization_notes)


@pytest.mark.parametrize(
    "socket_name",
    ["faultloggerd.server", "faultloggerd.sdkdump.server", "faultloggerd.crash.server"],
)
def test_socket_service_names_may_contain_dots(socket_name: str):
    target = normalize_target(f"/dev/unix/socket/{socket_name}")
    assert target.basename == socket_name
    assert target.service_hint == socket_name


def test_bare_macro_and_service_name_are_distinguished_without_guessing_repo():
    macro = normalize_target("请定位 PIPE_NAME")
    assert macro.target_type == "macro"
    assert macro.macro_hint == "PIPE_NAME"
    assert macro.socket_path is None

    service = normalize_target("请分析 ParamService 服务")
    assert service.target_type == "service_name"
    assert service.service_hint == "ParamService"
    assert service.target_revision == "unknown"
    assert any("尚未推断" in note for note in service.normalization_notes)


def test_local_absolute_path_is_not_misclassified_as_remote_socket():
    with pytest.raises(TargetNormalizationError, match="本地源码/工程路径"):
        normalize_target("/Users/shiyu/学习/hyl/new/OpenAnt/source_code_base/foo")


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("", "不能为空"),
        ("   ", "不能为空"),
        ("https://example.invalid/source", "URL"),
        ("/dev/unix/socket/../secret", "穿越"),
        ("/dev/unix/socket/paramservice\nnext", "控制字符"),
        ("没有可识别目标", "未识别"),
    ],
)
def test_invalid_or_ambiguous_input_fails_closed(value, message):
    with pytest.raises(TargetNormalizationError, match=message):
        normalize_target(value)


def test_initial_queries_are_stable_bounded_deduplicated_and_use_cxx():
    target = normalize_target("/dev/unix/socket/paramservice")
    first, second = build_initial_queries(target), build_initial_queries(target)
    assert first == second
    assert len(first) <= 12
    assert [query.query_id for query in first] == [f"Q-{index:04d}" for index in range(1, len(first) + 1)]
    assert len({(query.kind, query.value, query.file_type) for query in first}) == len(first)
    assert all(query.file_type in {"c", "cxx"} for query in first)
    assert all("cpp" not in query.to_dict()["params"].values() for query in first)
    assert first[0].kind == "definition"
    assert first[0].value == "paramservice"
    assert first[0].file_type == "c"
    assert first[1].file_type == "cxx"
    assert any(query.kind == "full" and query.value == "/dev/unix/socket/paramservice" for query in first)
    assert all(len(query.value) <= 512 for query in first)


def test_macro_queries_prioritize_macro_then_include_path_evidence():
    target = normalize_target("PIPE_NAME=/dev/unix/socket/paramservice")
    queries = build_initial_queries(target)
    assert [(query.kind, query.value) for query in queries[:4]] == [
        ("definition", "PIPE_NAME"),
        ("definition", "PIPE_NAME"),
        ("symbol", "PIPE_NAME"),
        ("symbol", "PIPE_NAME"),
    ]
    assert any(query.kind == "path" and query.value == "paramservice" for query in queries)


def test_service_query_plan_has_no_unbounded_full_text_search():
    target, queries = normalize_and_plan("paramservice", max_queries=3)
    assert target.target_type == "service_name"
    assert len(queries) == 3
    assert [query.query_id for query in queries] == ["Q-0001", "Q-0002", "Q-0003"]
    assert queries[-1].kind == "symbol"


def test_target_revision_and_query_limit_are_validated():
    with pytest.raises(TargetNormalizationError, match="revision"):
        normalize_target("paramservice", target_revision="../../main")
    target = normalize_target("paramservice")
    with pytest.raises(TargetNormalizationError, match="max_queries"):
        build_initial_queries(target, max_queries=0)
    with pytest.raises(TargetNormalizationError, match="file_type"):
        LocatorQuery("Q-0001", "path", "paramservice", "cpp", "bad")
