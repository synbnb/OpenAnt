"""Contract tests for the bounded OpenHarmony IDL parser."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.idl import OpenHarmonyIDLParser  # noqa: E402


def test_parser_extracts_interface_methods_directions_types_and_declarations():
    text = r'''
        /* comments and strings must remain inert: interface("not_a_contract"); */
        package OHOS.Security;
        import CommonTypes;
        sequenceable OHOS.Security.ParcelData;
        sequenceable Alias..OHOS.Security.OtherData;
        interface OHOS.Security.ICallback;

        enum AccessMode {
            NONE = 0,
            READ,
        };
        struct RequestData {
            String name;
            int count;
        };

        interface OHOS.Security.IService {
            void Send([in] String value, [out] List<int> results);
            int Update([inout] int[] values);
            void Register([in] OHOS.Security.ICallback callback);
        }
    '''

    result = OpenHarmonyIDLParser().parse_text("interfaces/IService.idl", text)

    assert result.parse_failures == []
    assert result.package == "OHOS.Security"
    assert result.imports == ["CommonTypes"]
    assert result.sequenceables == [
        "OHOS.Security.ParcelData",
        "Alias..OHOS.Security.OtherData",
    ]
    assert result.enums[0].name == "AccessMode"
    assert result.enums[0].values == ["NONE = 0", "READ"]
    assert [field.name for field in result.structs[0].fields] == ["name", "count"]

    callback = next(interface for interface in result.interfaces if interface.name.endswith("ICallback"))
    service = next(interface for interface in result.interfaces if interface.name.endswith("IService"))
    assert callback.forward_declaration is True
    assert service.forward_declaration is False
    assert [method.name for method in service.methods] == ["Send", "Update", "Register"]
    assert service.methods[0].return_type == "void"
    assert [(param.direction, param.type, param.name) for param in service.methods[0].parameters] == [
        ("in", "String", "value"),
        ("out", "List<int>", "results"),
    ]
    assert service.methods[1].parameters[0].direction == "inout"
    assert service.methods[1].parameters[0].type == "int[]"


def test_parser_extracts_method_annotations_and_ipccode_metadata():
    result = OpenHarmonyIDLParser().parse_text(
        "interfaces/IDisplayManager.idl",
        """
        interface OHOS.Rosen.IDisplayManager {
            [ipccode 0] void GetSession([out] IRemoteObject service);
            [ ipccode 42 ] [oneway] void NotifyChange([in] int state);
        }
        """,
    )

    service = result.interfaces[0]
    assert [method.name for method in service.methods] == ["GetSession", "NotifyChange"]
    assert service.methods[0].ipc_code == 0
    assert service.methods[0].annotations == ["ipccode 0"]
    assert service.methods[1].ipc_code == 42
    assert service.methods[1].annotations == ["ipccode 42", "oneway"]
    assert service.methods[1].to_dict()["ipc_code"] == 42


def test_parser_reports_unbalanced_interface_without_executing_content():
    result = OpenHarmonyIDLParser().parse_text(
        "broken/IService.idl",
        'interface OHOS.Broken.IService {\n  void Run([in] String value);\n',
    )

    assert result.interfaces == []
    assert result.parse_failures == [
        {
            "path": "broken/IService.idl",
            "reason": "unbalanced interface block: OHOS.Broken.IService",
        }
    ]


def test_repository_collection_is_bounded_and_rejects_symlink_escape(tmp_path: Path):
    (tmp_path / "IService.idl").write_text(
        'interface OHOS.Security.IService { void Run(); }\n', encoding="utf-8"
    )
    (tmp_path / "oversized.idl").write_bytes(b"x" * (1024 * 1024 + 1))
    outside = tmp_path.parent / "openant-idl-outside.idl"
    outside.write_text('interface OHOS.Security.Outside {};\n', encoding="utf-8")
    try:
        (tmp_path / "escape.idl").symlink_to(outside)
    except OSError:
        pytest.skip("filesystem does not support symlinks")

    result = OpenHarmonyIDLParser().collect(tmp_path)

    assert result.files == ["IService.idl"]
    assert [interface.name for interface in result.interfaces] == ["OHOS.Security.IService"]
    assert result.parse_failures == [
        {
            "path": "oversized.idl",
            "reason": "IDL file exceeds 1048576 bytes",
        }
    ]


def test_reference_openharmony_idl_files_are_parsed_when_corpus_is_configured():
    configured_root = os.environ.get("OPENHARMONY_CORPUS_ROOT")
    if not configured_root:
        pytest.skip("set OPENHARMONY_CORPUS_ROOT to run the six-IDL smoke check")

    files = [
        "communication_netmanager_base/interfaces/innerkits/netstatsclient/INetStatsService.idl",
        "communication_wifi/wifi/frameworks/native/HotspotTypes.idl",
        "communication_wifi/wifi/frameworks/native/IWifiHotspot.idl",
        "communication_wifi/wifi/frameworks/native/IWifiHotspotMgr.idl",
        "communication_wifi/wifi/frameworks/native/IWifiScan.idl",
        "communication_wifi/wifi/frameworks/native/IWifiScanMgr.idl",
    ]
    parser = OpenHarmonyIDLParser()
    for relative in files:
        result = parser.parse_file(Path(configured_root) / relative, relative_path=relative)
        assert result.parse_failures == [], relative
        assert result.interfaces or result.enums or result.structs, relative
