"""Tests for explainable OpenHarmony OpenGrok path ranking."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    PathClassificationError,
    classify_path,
    normalize_target,
    rank_paths,
)


FIXTURE = Path(__file__).parent / "fixtures" / "opengrok" / "live_1_14_11" / "search_full_paramservice_paths.json"


def test_production_source_and_header_are_classified_with_explanations():
    target = normalize_target("/dev/unix/socket/paramservice")
    implementation = classify_path(
        "/openharmony/base/startup/init/services/param/linux/param_service.c",
        target=target,
    )
    header = classify_path(
        "/openharmony/base/startup/init/services/param/include/param_utils.h",
        target=target,
    )
    assert implementation.role == "production"
    assert header.role == "production"
    assert implementation.score > 0
    assert header.score > 0
    assert {feature.code for feature in implementation.features} >= {
        "source",
        "implementation",
        "service_context",
        "target_basename",
    }
    assert any(feature.code == "header" for feature in header.features)


@pytest.mark.parametrize(
    ("path", "role"),
    [
        ("/openharmony/base/security/selinux_adapter/sepolicy/ohos_policy/system/foo.te", "selinux"),
        ("/openharmony/kernel/linux/drivers/foo.c", "kernel"),
        ("/openharmony/base/module/tests/foo_test.cpp", "test"),
        ("/openharmony/base/module/fuzz/foo_fuzzer.cpp", "fuzz"),
        ("/openharmony/out/rk3568/packages/phone/system/lib/libfoo.z.so", "generated"),
        ("/openharmony/base/third_party/lib/foo.cpp", "third_party"),
        ("/openharmony/base/hiview/logs/last_kmsg", "log"),
        ("/openharmony/base/module/build.gn", "build"),
    ],
)
def test_non_production_roles_are_downgraded_not_removed(path, role):
    classification = classify_path(path, target=normalize_target("paramservice"))
    assert classification.role == role
    assert classification.score < 0
    assert classification.features
    assert any(feature.weight < 0 for feature in classification.features)


def test_real_94_result_path_fixture_keeps_all_candidates_and_prioritizes_source():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert payload["result_count"] == 94
    assert len(payload["paths"]) == 94
    ranked = rank_paths(payload["paths"], target=normalize_target("/dev/unix/socket/paramservice"))
    assert len(ranked) == 94
    assert {item.role for item in ranked} >= {"generated", "selinux", "test", "production"}
    # The real full-path response contains this production header.  It must
    # outrank generated output and SELinux policy without deleting either.
    header_index = next(
        index for index, item in enumerate(ranked) if item.path.endswith("/param_utils.h")
    )
    assert header_index < next(index for index, item in enumerate(ranked) if item.role == "selinux")
    assert header_index < next(index for index, item in enumerate(ranked) if item.role == "generated")
    assert all(item.features for item in ranked)


def test_ranking_is_stable_and_deduplicates_only_exact_path_repeats():
    paths = [
        "/openharmony/base/startup/init/services/param/include/param_utils.h",
        "/openharmony/out/rk3568/startup/init/param",
        "/openharmony/base/startup/init/services/param/include/param_utils.h",
    ]
    first = rank_paths(paths, target=normalize_target("paramservice"))
    second = rank_paths(reversed(paths), target=normalize_target("paramservice"))
    assert [item.path for item in first] == [item.path for item in second]
    assert len(first) == 2
    assert first[0].path.endswith("param_utils.h")


@pytest.mark.parametrize(
    "path",
    [
        "",
        "foo/../bar.c",
        "https://example.invalid/foo.c",
        "foo\\bar.c",
        "/tmp/a?b",
        "/tmp/a\nb",
        "/tmp/" + ("a" * 2049),
    ],
)
def test_unsafe_candidate_path_fails_closed(path):
    with pytest.raises(PathClassificationError):
        classify_path(path)


def test_unknown_file_is_kept_with_explainable_unknown_role():
    result = classify_path("/openharmony/base/startup/init/param", target=normalize_target("paramservice"))
    assert result.role == "unknown"
    assert any(feature.code == "unknown" and feature.weight < 0 for feature in result.features)
    assert result.features[0].code == "unknown"
