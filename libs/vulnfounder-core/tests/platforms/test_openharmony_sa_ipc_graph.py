"""Tests for SA-profile to IDL/interface semantic graph association."""

from __future__ import annotations

import json
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.idl import OpenHarmonyIDLParser  # noqa: E402
from core.platforms.openharmony.ipc_graph import OpenHarmonyIPCResolver  # noqa: E402
from core.platforms.openharmony.sa_profile import OpenHarmonySAProfileParser  # noqa: E402


def _idl(text: str):
    return OpenHarmonyIDLParser().parse_text("interfaces/service.idl", text)


def _sa(relative_path: str, payload: dict):
    return OpenHarmonySAProfileParser().parse_text(
        relative_path, json.dumps(payload), format_hint="json"
    )


def _edge(graph, kind: str):
    return next(edge for edge in graph.edges.values() if edge.kind == kind)


def test_resolver_links_sa_profile_to_interface_and_preserves_metadata():
    idl = _idl("interface OHOS.Health.IHealthService { int Enable(); }")
    sa = _sa(
        "sa_profile/3605.json",
        {
            "process": "health_service",
            "systemability": [
                {
                    "name": 3605,
                    "libpath": "libhealth_service.z.so",
                    "permissions": ["ohos.permission.HEALTH_DATA"],
                    "extension": ["backup"],
                    "run-on-create": True,
                    "distributed": False,
                    "dump-level": 1,
                }
            ],
        },
    )

    graph = OpenHarmonyIPCResolver().resolve(idl, {}, sa)

    sa_node = graph.nodes["sa:3605"]
    assert sa_node.kind == "system_ability"
    assert sa_node.attributes["process"] == "health_service"
    assert sa_node.attributes["libpath"] == "libhealth_service.z.so"
    assert sa_node.attributes["permissions"] == ["ohos.permission.HEALTH_DATA"]
    assert sa_node.attributes["run_on_create"] == [True]
    edge = _edge(graph, "system_ability_to_interface")
    assert edge.source_id == "sa:3605"
    assert edge.target_id == "idl:interface:OHOS.Health.IHealthService"
    assert edge.confidence == 0.95
    assert edge.evidence[0]["signal"] == "interface_stem_in_sa_libpath_or_process"
    assert not any(
        orphan["kind"]
        in {
            "ambiguous_system_ability_interface",
            "unresolved_interface_system_ability",
            "unresolved_system_ability_interface",
        }
        for orphan in graph.orphans
    )


def test_resolver_uses_native_owner_path_as_secondary_sa_signal():
    idl = _idl("interface OHOS.Audio.IAudioService { int Start(); }")
    sa = _sa(
        "sa_profile/4100.json",
        {
            "process": "foundation",
            "systemability": [{"name": 4100, "libpath": "libcomponent.z.so"}],
        },
    )
    functions = {
        "audio.cpp:AudioService::Start": {
            "name": "AudioService::Start",
            "file_path": "services/component/audio_service.cpp",
            "start_line": 20,
            "code": "return 0;",
        }
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, functions, sa)

    edge = _edge(graph, "system_ability_to_interface")
    assert edge.confidence == 0.85
    assert edge.evidence[0]["signal"] == "interface_owner_in_sa_native_path"
    assert edge.evidence[0]["matched"] == []


def test_resolver_keeps_ambiguous_and_unmatched_sa_links_as_orphans():
    idl = _idl("interface OHOS.Health.IHealthService { int Enable(); }")
    sa = OpenHarmonySAProfileParser().parse_text(
        "sa_profile/a.json",
        json.dumps(
            {
                "process": "foundation",
                "systemability": {
                    "name": 5001,
                    "libpath": "libhealth_service_a.z.so",
                },
            }
        ),
        format_hint="json",
    )
    second = _sa(
        "sa_profile/b.json",
        {
            "process": "foundation",
            "systemability": {
                "name": 5002,
                "libpath": "libhealth_service_b.z.so",
            },
        },
    )
    third = _sa(
        "sa_profile/c.json",
        {
            "process": "foundation",
            "systemability": {"name": 5003, "libpath": "libunrelated.z.so"},
        },
    )
    sa.extend(second)
    sa.extend(third)

    graph = OpenHarmonyIPCResolver().resolve(idl, {}, sa)

    assert not any(edge.kind == "system_ability_to_interface" for edge in graph.edges.values())
    ambiguous = [
        orphan
        for orphan in graph.orphans
        if orphan["kind"] == "ambiguous_system_ability_interface"
    ]
    assert len(ambiguous) == 1
    assert {item["sa_id"] for item in ambiguous[0]["evidence"]} == {"5001", "5002"}
    unresolved_sa = [
        orphan
        for orphan in graph.orphans
        if orphan["kind"] == "unresolved_system_ability_interface"
    ]
    assert {orphan["attributes"]["sa_id"] for orphan in unresolved_sa} == {
        "5001",
        "5002",
        "5003",
    }


def test_resolver_accepts_serialized_sa_result_shape():
    idl = _idl("interface OHOS.Health.IHealthService { void Ping(); }")
    sa = {
        "profiles": [
            {
                "path": "sa_profile/3605.json",
                "process": "health_service",
                "system_abilities": [
                    {"sa_id": "3605", "libpath": "libhealth_service.z.so"}
                ],
            }
        ]
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, {}, sa)

    assert any(edge.kind == "system_ability_to_interface" for edge in graph.edges.values())
    assert graph.nodes["sa:3605"].attributes["libpaths"] == ["libhealth_service.z.so"]
