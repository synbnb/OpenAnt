"""Contract tests for the bounded OpenHarmony SA profile parser."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.sa_profile import OpenHarmonySAProfileParser  # noqa: E402


def test_parser_extracts_json_systemability_metadata():
    payload = {
        "process": "wifi_manager_service",
        "systemability": [
            {
                "name": 1123,
                "libpath": "libwifi_p2p_ability.z.so",
                "run-on-create": False,
                "auto-restart": True,
                "distributed": False,
                "dump-level": 1,
                "extension": ["backup", "restore"],
            }
        ],
    }

    result = OpenHarmonySAProfileParser().parse_text(
        "sa_profile/1123.json", json.dumps(payload), format_hint="json"
    )

    assert result.parse_failures == []
    assert result.profiles[0].format == "json"
    assert result.profiles[0].process == "wifi_manager_service"
    ability = result.profiles[0].system_abilities[0]
    assert ability.sa_id == "1123"
    assert ability.libpath == "libwifi_p2p_ability.z.so"
    assert ability.run_on_create is False
    assert ability.auto_restart is True
    assert ability.extension == ["backup", "restore"]


def test_parser_extracts_xml_systemability_metadata():
    text = """
        <info>
          <process>sensors</process>
          <systemability>
            <name>3605</name>
            <libpath>libmedical_service.z.so</libpath>
            <run-on-create>true</run-on-create>
            <distributed>false</distributed>
            <dump-level>1</dump-level>
          </systemability>
        </info>
    """

    result = OpenHarmonySAProfileParser().parse_text(
        "sa_profile/3605.xml", text, format_hint="xml"
    )

    assert result.parse_failures == []
    ability = result.profiles[0].system_abilities[0]
    assert result.profiles[0].format == "xml"
    assert result.profiles[0].process == "sensors"
    assert ability.sa_id == "3605"
    assert ability.run_on_create is True
    assert ability.distributed is False
    assert ability.dump_level == 1


def test_parser_rejects_xml_entities_and_keeps_failure_auditable():
    result = OpenHarmonySAProfileParser().parse_text(
        "sa_profile/unsafe.xml",
        '<!DOCTYPE info [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><info>&xxe;</info>',
        format_hint="xml",
    )

    assert result.profiles == []
    assert result.parse_failures == [
        {
            "path": "sa_profile/unsafe.xml",
            "reason": "XML entities and doctypes are not allowed",
        }
    ]


def test_repository_collection_only_reads_sa_profile_files(tmp_path: Path):
    profile_dir = tmp_path / "sa_profile"
    profile_dir.mkdir()
    (profile_dir / "1001.json").write_text(
        json.dumps(
            {
                "process": "demo",
                "systemability": {"name": 1001, "libpath": "libdemo.z.so"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "unrelated.xml").write_text(
        "<project><name>test</name></project>", encoding="utf-8"
    )

    result = OpenHarmonySAProfileParser().collect(tmp_path)

    assert result.files == ["sa_profile/1001.json"]
    assert result.profiles[0].system_abilities[0].sa_id == "1001"
    assert result.parse_failures == []


def test_reference_openharmony_sa_profiles_are_parsed_when_corpus_is_configured():
    configured_root = os.environ.get("OPENHARMONY_CORPUS_ROOT")
    if not configured_root:
        pytest.skip("set OPENHARMONY_CORPUS_ROOT to run the reference SA profile smoke check")

    result = OpenHarmonySAProfileParser().collect(Path(configured_root))

    assert result.parse_failures == []
    assert len(result.files) >= 13
    assert "sensors_medical_sensor/sa_profile/3605.xml" in result.files
    assert "communication_wifi/wifi/services/wifi_standard/sa_profile/1123.json" in result.files
    assert any(
        ability.sa_id == "3605"
        for profile in result.profiles
        for ability in profile.system_abilities
    )
