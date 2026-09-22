"""CLI/event_bus 通用载体的契约和安全边界测试。"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from utilities.openharmony_dynamic.contract_validator import validate_contract
from utilities.openharmony_dynamic.models import (
    ArtifactForm,
    CleanupSpec,
    Contract,
    EntrySpec,
    FaultSpec,
    IdentitySpec,
    OracleSpec,
    ProtocolSpec,
    RiskSpec,
)
from utilities.openharmony_dynamic.transports.command import (
    DeviceCommandTransport,
    command_argv_for,
    validate_command_argv,
)


class _FakeHdc:
    def __init__(self, returncode: int = 0):
        self.returncode = returncode
        self.calls: list[tuple[list[str], str]] = []

    def shell(self, argv, *, purpose="", **kwargs):
        self.calls.append((list(argv), purpose))
        return SimpleNamespace(
            returncode=self.returncode,
            stdout="accepted response" if self.returncode == 0 else "rejected",
            stderr="",
            to_dict=lambda: {
                "argv": list(argv), "returncode": self.returncode, "purpose": purpose,
            },
        )


def test_command_argv_rejects_shell_strings_and_shell_c():
    assert validate_command_argv("hidumper -s 123") == []
    assert validate_command_argv(["sh", "-c", "echo unsafe"]) == []
    assert validate_command_argv(["tool", "x;echo unsafe"]) == []
    assert validate_command_argv(["tool", "--name", "safe-value"]) == [
        "tool", "--name", "safe-value"
    ]


def test_cli_transport_executes_declared_argv_and_records_response():
    hdc = _FakeHdc()
    protocol = ProtocolSpec(
        descriptor_id="sp_daemon_text",
        param_space={"cli_argv": ["hidumper", "-s", "123", "-a", "status"]},
    )
    argv, key = command_argv_for(protocol, "cli")
    assert argv[-1] == "status"
    assert key == "cli_argv"

    result = DeviceCommandTransport(hdc, kind="cli").send(protocol, purpose="test:cli")

    assert result.reachability == "INPUT_DELIVERED"
    assert hdc.calls == [
        (["hidumper", "-s", "123", "-a", "status"], "test:cli")
    ]
    assert result.response_excerpt == "accepted response"
    assert result.transport["shell"] is False
    assert result.transport["argv_source"] == "cli_argv"


def test_event_bus_nonzero_device_result_is_rejected_not_infrastructure_error():
    hdc = _FakeHdc(returncode=1)
    protocol = ProtocolSpec(
        descriptor_id="sp_daemon_text",
        param_space={"event_argv": ["event-publisher", "--domain", "demo", "--name", "probe"]},
    )
    result = DeviceCommandTransport(hdc, kind="event_bus").send(protocol, purpose="test:event")
    assert result.reachability == "INPUT_REJECTED"
    assert "rc=1" in result.detail
    assert result.transport["argv_source"] == "event_argv"


def test_invalid_cli_contract_is_rejected_before_device_execution():
    contract = Contract(
        contract_id="cli-contract",
        finding_ids=["finding"],
        unit_id="unit",
        vuln_class="command_injection",
        entry=EntrySpec(kind="cli"),
        identity=IdentitySpec(),
        protocol=ProtocolSpec(
            descriptor_id="sp_daemon_text",
            param_space={"cli_argv": "hidumper -s 123"},
        ),
        fault=FaultSpec(operator="payload_value_substitution"),
        oracle=OracleSpec(
            kind="artifact_differential",
            artifact_forms=[ArtifactForm(
                form="create", path="/data/local/tmp/vf/marker", content_contains="__RUN_PATTERN__",
            )],
            refutation=["marker absent in independent baseline"],
        ),
        risk=RiskSpec(target_process="demo"),
        cleanup=CleanupSpec(),
    )

    errors = validate_contract(contract)

    assert any("必须提供字符串 argv 数组" in error for error in errors)

