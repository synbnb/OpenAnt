"""Contract tests for the bounded, static OpenHarmony GN parser."""

from __future__ import annotations

import sys
import os
from pathlib import Path

import pytest


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.gn import OpenHarmonyGNParser  # noqa: E402


def test_parser_extracts_common_target_metadata_and_unknown_conditions():
    text = r'''
        # A quoted string mentioning executable("not_a_target") is not a target.
        import("//build/ohos.gni")

        ohos_shared_library("health_sensor") {
          sources = [ "services/health_sensor.cpp", "services/parcel.cpp" ]
          deps = [ ":health_sensor_core", "//foundation:base" ]
          external_deps = [ "ipc:ipc_core", "hilog:libhilog" ]
          defines = [ "ENABLE_SENSOR", "VALUE=1" ]
          include_dirs = [ "include", "//foundation/include" ]
          if (is_linux) {
            sources += [ "services/linux_only.cpp" ]
          } else if (defined(ohos_lite)) {
            sources += [ "services/lite_only.cpp" ]
          }
        }
    '''

    result = OpenHarmonyGNParser().parse_text("services/BUILD.gn", text)

    assert result.parse_failures == []
    assert result.unknown_condition_count == 2
    assert len(result.targets) == 1
    target = result.targets[0]
    assert target.kind == "ohos_shared_library"
    assert target.name == "health_sensor"
    assert target.role == "production"
    assert target.sources == [
        "services/health_sensor.cpp",
        "services/parcel.cpp",
        "services/linux_only.cpp",
        "services/lite_only.cpp",
    ]
    assert target.deps == [":health_sensor_core", "//foundation:base"]
    assert target.external_deps == ["ipc:ipc_core", "hilog:libhilog"]
    assert target.defines == ["ENABLE_SENSOR", "VALUE=1"]
    assert target.include_dirs == ["include", "//foundation/include"]
    assert target.path == "services/BUILD.gn"
    assert target.unknown_conditions == ["is_linux", "defined(ohos_lite)"]


def test_parser_classifies_test_and_fuzz_targets_without_executing_content():
    text = r'''
        executable("ordinary_test") {
          sources = [ "ordinary_test.cpp" ]
        }

        ohos_unittest("PinAuthHdiUtTest") {
          sources = [ "pin_auth_test.cpp" ]
        }

        ohos_fuzztest("PinAuthExecutorStubFuzzTest") {
          # This string must remain inert; the parser must never execute it.
          script = "raise RuntimeError('repository code executed')"
          sources = [ "pin_auth_executor_stub_fuzzer.cpp" ]
        }
    '''

    result = OpenHarmonyGNParser().parse_text("test/BUILD.gn", text)

    assert [target.role for target in result.targets] == ["test", "test", "fuzz"]
    assert result.targets[0].is_test is True
    assert result.targets[1].is_test is True
    assert result.targets[2].is_fuzz is True
    assert all(target.sources for target in result.targets)


def test_parser_collects_config_include_dirs_and_cflags():
    result = OpenHarmonyGNParser().parse_text(
        "core/BUILD.gn",
        'config("core_config") {\n'
        '  include_dirs = [ "include" ]\n'
        '  cflags_cc = [ "-DCORE_ENABLED" ]\n'
        '}\n',
    )

    assert len(result.targets) == 1
    target = result.targets[0]
    assert target.kind == "config"
    assert target.include_dirs == ["include"]
    assert target.cflags_cc == ["-DCORE_ENABLED"]


def test_parser_reports_unbalanced_target_and_keeps_safe_result():
    result = OpenHarmonyGNParser().parse_text(
        "broken/BUILD.gn",
        'ohos_shared_library("broken") {\n  sources = [ "broken.cpp" ]\n',
    )

    assert result.targets == []
    assert result.parse_failures == [
        {"path": "broken/BUILD.gn", "reason": "unbalanced target block: broken"}
    ]


def test_repository_collection_is_bounded_and_records_oversized_files(tmp_path: Path):
    (tmp_path / "BUILD.gn").write_text(
        'group("root") {\n  deps = [ ":child" ]\n}\n', encoding="utf-8"
    )
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "BUILD.gni").write_text(
        'source_set("child") {\n  sources = [ "child.cpp" ]\n}\n', encoding="utf-8"
    )
    (tmp_path / "oversized.gn").write_bytes(b"x" * (1024 * 1024 + 1))

    result = OpenHarmonyGNParser(max_file_bytes=1024 * 1024).collect(tmp_path)

    assert [target.name for target in result.targets] == ["root", "child"]
    assert result.files == ["BUILD.gn", "sub/BUILD.gni"]
    assert result.unknown_condition_count == 0
    assert result.parse_failures == [
        {
            "path": "oversized.gn",
            "reason": "GN file exceeds 1048576 bytes",
        }
    ]


def test_repository_collection_rejects_symlink_escape(tmp_path: Path):
    outside = tmp_path.parent / "openant-gn-outside.gn"
    outside.write_text('group("outside") {}\n', encoding="utf-8")
    try:
        (tmp_path / "BUILD.gn").symlink_to(outside)
    except OSError:
        pytest.skip("filesystem does not support symlinks")

    result = OpenHarmonyGNParser().collect(tmp_path)

    assert result.targets == []
    assert result.files == []
    assert result.parse_failures == []
    direct = OpenHarmonyGNParser().parse_file(
        tmp_path / "BUILD.gn", relative_path="BUILD.gn"
    )
    assert direct.parse_failures == [
        {"path": "BUILD.gn", "reason": "symlink GN file is not allowed"}
    ]


def test_reference_openharmony_gn_files_are_parsed_when_corpus_is_configured():
    configured_root = os.environ.get("OPENHARMONY_CORPUS_ROOT")
    if not configured_root:
        pytest.skip("set OPENHARMONY_CORPUS_ROOT to run the reference GN smoke check")

    cases = {
        "sensors_medical_sensor/services/medical_sensor/BUILD.gn": "libmedical_service",
        "communication_netmanager_base/services/netconnmanager/BUILD.gn": "net_conn_manager",
        "drivers_peripheral/pin_auth/test/unittest/pin_auth/BUILD.gn": "PinAuthHdiUtTest",
        "drivers_peripheral/pin_auth/test/fuzztest/pin_auth/pinauthexecutorstub_fuzzer/BUILD.gn": (
            "PinAuthExecutorStubFuzzTest"
        ),
    }
    parser = OpenHarmonyGNParser()
    for relative, expected_target in cases.items():
        result = parser.parse_file(
            Path(configured_root) / relative,
            relative_path=relative,
        )
        assert result.parse_failures == [], relative
        assert expected_target in {target.name for target in result.targets}, relative
