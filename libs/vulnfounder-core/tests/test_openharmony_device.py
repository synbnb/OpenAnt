"""离线测试 OpenHarmony 真机动态验证后端的预算、产物和只读边界。"""

import json
from pathlib import Path


def _pipeline(path: Path) -> None:
    path.write_text(json.dumps({
        "repository": {"name": "fixture-oh", "language": "c"},
        "findings": [{
            "id": "OH-DYN-001",
            "name": "socket candidate",
            "stage1_verdict": "vulnerable",
            "stage2_verdict": "confirmed",
            "location": {"file": "src/service.cpp", "function": "Service::OnRemoteRequest"},
            "attack_scenario": "外部端点输入到服务命令参数。",
        }],
    }), encoding="utf-8")


def test_device_runner_preflight_and_artifacts_without_model(tmp_path, monkeypatch):
    from core.exposure_surface import HDCResult
    import utilities.dynamic_tester.openharmony_device as module

    class FakeHDC:
        def __init__(self, *args, **kwargs):
            self.serial = args[1]

        def run_agent(self, command, timeout_seconds=None):
            return HDCResult("agent_command", ("hdc", "shell", command), 0, f"ok:{command}\n", "", 1, False)

    monkeypatch.setattr(module, "HDCClient", FakeHDC)
    monkeypatch.setattr(module, "resolve_hdc_path", lambda: "/tmp/hdc")
    monkeypatch.setattr(module, "_run_host", lambda *args: (0, "serial\tUSB\tConnected\n", "", 1))

    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    summary = module.run_openharmony_device(
        str(pipeline), str(tmp_path / "out"),
        serial="fixture-serial",
        binding=None,
        max_rounds=2,
        max_commands=8,
    )
    assert summary["candidate_count"] == 1
    assert summary["command_count"] == 6
    run_dir = Path(summary["run_dir"])
    assert (run_dir / "device_preflight.json").is_file()
    assert (run_dir / "task_tree.json").is_file()
    assert (run_dir / "device_commands.jsonl").is_file()
    assert (run_dir / "poc/OH-DYN-001/POC_PLAN.zh-CN.md").is_file()
    assert (run_dir / "exp/OH-DYN-001/collect_evidence.sh").is_file()
    assert summary["results"][0]["status"] == "BLOCKED"


def test_device_state_change_is_blocked_by_default(tmp_path, monkeypatch):
    from core.exposure_surface import HDCResult
    import utilities.dynamic_tester.openharmony_device as module

    class FakeHDC:
        def __init__(self, *args, **kwargs):
            pass

        def run_agent(self, command, timeout_seconds=None):
            raise AssertionError("state-changing command must not reach HDC")

    monkeypatch.setattr(module, "HDCClient", FakeHDC)
    monkeypatch.setattr(module, "resolve_hdc_path", lambda: "/tmp/hdc")
    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(serial="fixture-serial"),
        binding=None,
    )
    outcome = runner._device_exec({"command": "param set demo 1", "purpose": "test", "state_change": True})
    assert outcome["status"] == "blocked"
    assert outcome["requires_allow_state_change"] is True


def test_service_liveness_requires_successful_sample_and_detects_transient_exit():
    import utilities.dynamic_tester.openharmony_device as module

    observed = module._evaluate_service_liveness(
        ["100"],
        [
            {"index": 0, "valid": True, "pids": [], "evidence_id": "E1"},
            {"index": 1, "valid": True, "pids": ["200"], "evidence_id": "E2"},
        ],
        expected_effect="service_crash",
    )
    assert observed["crash_observed"] is True
    assert observed["first_disappearance_sample"] == 0
    assert observed["disappeared_pids"] == ["100"]
    assert observed["restarted"] is True
    assert observed["observation_complete"] is True


def test_service_liveness_does_not_treat_failed_pidof_as_crash():
    import utilities.dynamic_tester.openharmony_device as module

    observed = module._evaluate_service_liveness(
        ["100"],
        [
            {"index": 0, "valid": False, "pids": [], "evidence_id": "E1"},
            {"index": 1, "valid": True, "pids": ["100"], "evidence_id": "E2"},
        ],
        expected_effect="service_crash",
    )
    assert observed["crash_observed"] is False
    assert observed["first_disappearance_sample"] is None
    assert observed["observation_complete"] is False


def test_service_liveness_requires_declared_crash_effect():
    import utilities.dynamic_tester.openharmony_device as module

    observed = module._evaluate_service_liveness(
        ["100"],
        [{"index": 0, "valid": True, "pids": [], "evidence_id": "E1"}],
        expected_effect="marker",
    )
    assert observed["crash_observed"] is False


def test_input_influence_is_a_separate_non_confirming_evidence_level():
    import utilities.dynamic_tester.openharmony_device as module

    observed = module._classify_observed_effect(
        expected_effect="marker",
        marker_match=False,
        service_crash_observed=False,
        artifact_created=False,
        target_reached=True,
        carrier_sent=True,
        sink_reached=True,
        input_influence_proven=True,
    )
    assert observed["status"] == "NOT_REPRODUCED"
    assert observed["verification_level"] == "input_influence_proven"
    assert observed["input_influence"] == "proven"
    assert observed["effect_observed"] is False


def test_finish_recovers_known_ids_from_blocked_details_but_requires_explicit_confirmed_ids(tmp_path, monkeypatch):
    from core.exposure_surface import HDCResult
    import utilities.dynamic_tester.openharmony_device as module

    class FakeHDC:
        def __init__(self, *args, **kwargs):
            pass

        def run_agent(self, command, timeout_seconds=None):
            return HDCResult("agent_command", ("hdc", "shell", command), 0, "observed\n", "", 1, False)

    monkeypatch.setattr(module, "HDCClient", FakeHDC)
    monkeypatch.setattr(module, "resolve_hdc_path", lambda: "/tmp/hdc")
    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(serial="fixture-serial"),
        binding=None,
    )
    runner._preflight()
    blocked = runner._finish_dynamic({
        "results": [{
            "finding_id": "OH-DYN-001",
            "status": "BLOCKED",
            "details": "设备事实见 OHDEV-EV-0001",
        }],
    })
    assert blocked["accepted"] == 1
    assert runner.decisions["OH-DYN-001"]["evidence_ids"] == ["OHDEV-EV-0001"]
    confirmed = runner._finish_dynamic({
        "results": [{
            "finding_id": "OH-DYN-001",
            "status": "CONFIRMED",
            "details": "设备事实见 OHDEV-EV-0001",
        }],
    })
    assert confirmed["accepted"] == 0


def test_finish_cannot_downgrade_authoritative_carrier_result(tmp_path):
    """模型收尾不得覆盖已经由受审查载体得到的设备结论。"""

    import utilities.dynamic_tester.openharmony_device as module

    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(serial="fixture-serial"),
        hdc_path="/tmp/hdc",
    )
    runner.evidence = [{"evidence_id": "OHDEV-EV-0001"}]
    runner.carrier_results["OH-DYN-001"] = {
        "status": "CONFIRMED",
        "finding_id": "OH-DYN-001",
        "details": "设备 canary 已由本轮载体创建",
        "evidence_ids": ["OHDEV-EV-0001"],
        "target_reached": True,
        "verification_level": "effect_confirmed",
        "marker": {"attributed_to_attempt": True},
    }

    outcome = runner._finish_dynamic({
        "results": [{
            "finding_id": "OH-DYN-001",
            "status": "INCONCLUSIVE",
            "details": "模型认为设备证据不足",
            "evidence_ids": ["OHDEV-EV-0001"],
        }],
    })

    assert outcome["accepted"] == 1
    decision = runner.decisions["OH-DYN-001"]
    assert decision["status"] == "CONFIRMED"
    assert decision["decision_source"] == "validated_carrier"
    assert decision["model_assessment"]["status"] == "INCONCLUSIVE"
    assert decision["model_status_conflict"] == {
        "carrier_status": "CONFIRMED",
        "model_status": "INCONCLUSIVE",
    }


def test_generated_safe_probe_scripts_execute_and_record_evidence(tmp_path):
    import stat
    import utilities.dynamic_tester.openharmony_device as module

    fake_hdc = tmp_path / "fake-hdc"
    fake_hdc.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('fake-device:' + ' '.join(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    fake_hdc.chmod(fake_hdc.stat().st_mode | stat.S_IXUSR)
    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(serial="fixture-serial", max_commands=32),
        hdc_path=str(fake_hdc),
    )
    finding = json.loads(pipeline.read_text(encoding="utf-8"))["findings"][0]
    finding["device_artifacts"] = runner._candidate_artifacts(finding)
    poc = runner._run_generated_probe("OH-DYN-001", "poc")
    exp = runner._run_generated_probe("OH-DYN-001", "exp")
    assert poc["status"] == "executed"
    assert exp["status"] == "executed"
    assert poc["evidence_ids"]
    assert exp["evidence_ids"]
    assert (runner.run_dir / "poc/OH-DYN-001/execution/poc_execution.json").is_file()
    assert (runner.run_dir / "exp/OH-DYN-001/execution/exp_execution.json").is_file()
    assert all(item["state_change"] is False for item in runner.commands)


def test_socket_endpoint_hint_only_adds_validated_read_only_commands():
    import utilities.dynamic_tester.openharmony_device as module

    finding = {
        "id": "SOCKET-001",
        "attack_scenario": "外部入口为 /dev/unix/socket/paramservice；仅做设备事实核对。",
    }
    spec = module._probe_spec(finding)
    assert spec["endpoint_hint"] == {"kind": "unix", "value": "/dev/unix/socket/paramservice"}
    commands = [item["command"] for item in spec["poc_commands"] + spec["exp_commands"]]
    assert "ls -lZ /dev/unix/socket/paramservice" in commands
    assert all(module._SAFE_REMOTE_COMMAND_RE.fullmatch(command) for command in commands)


def test_native_event_raw_builder_preserves_reviewed_fields_without_shell_execution():
    import struct
    import utilities.dynamic_tester.openharmony_device as module

    payload = module._build_native_event_raw({
        "first": '{"domain":"AAFWK","stringid":"THREAD_BLOCK_6S",'
        '"packageName":"hiview;echo hack","processName":"hiview"}',
    })
    assert len(payload) == int.from_bytes(payload[:4], "little", signed=True)
    assert len(payload) >= 85
    # UID/PID are intentionally placeholders.  The reviewed native helper
    # patches these two fields from SCM credentials at send time.
    assert payload[4 + 59:4 + 67] == b"\x00" * 8
    assert b"hiview;echo hack" in payload
    # Public EventRaw omits only the final log byte of the 81-byte packed
    # header; the device-side converter inserts it before decoding.  Therefore
    # paramCnt starts at 4 + 80 bytes.
    assert struct.unpack_from("<i", payload, 84)[0] == 2
    # The packed value-type byte must decode to STRING=12 (0x18 includes the
    # one-bit ``isArray`` prefix), and the parameter stream must retain
    # numeric PID/UID fields instead of silently dropping them.
    payload_with_numeric = module._build_native_event_raw({
        "first": '{"domain":"AAFWK","stringid":"THREAD_BLOCK_6S",'
        '"pid":0,"uid":0,"packageName":"hiview","processName":"hiview"}',
    })
    assert struct.unpack_from("<i", payload_with_numeric, 84)[0] == 4
    assert b"PID\x10" in payload_with_numeric
    assert b"UID\x10" in payload_with_numeric
    assert b"PACKAGE_NAME\x18" in payload_with_numeric


def test_native_carrier_manifest_requires_hashed_helper(tmp_path):
    import hashlib
    import utilities.dynamic_tester.openharmony_device as module

    carrier = tmp_path / "carriers" / "HV-TEST"
    carrier.mkdir(parents=True)
    hap = carrier / "entry-default-signed.hap"
    helper = carrier / "vf_native_datagram_sender"
    hap.write_bytes(b"reviewed-hap")
    helper.write_bytes(b"reviewed-native-helper")
    hap_sha = hashlib.sha256(hap.read_bytes()).hexdigest()
    helper_sha = hashlib.sha256(helper.read_bytes()).hexdigest()
    (carrier / "manifest.txt").write_text(
        "\n".join([
            "id=HV-TEST", "mode=native", "host=", "port=0",
            "local_path=/dev/unix/socket/hisysevent",
            "marker=/data/local/tmp/vf_hv_test.txt",
            "native_helper=vf_native_datagram_sender",
            f"native_helper_sha256={helper_sha}",
            'first={"domain":"AAFWK","stringid":"THREAD_BLOCK_6S","packageName":"hiview"}',
            f"sha256={hap_sha}",
        ]) + "\n", encoding="utf-8",
    )
    parsed = module._parse_carrier_manifest(carrier / "manifest.txt", hap, "HV-TEST")
    assert parsed["mode"] == "native"
    assert parsed["endpoint"]["kind"] == "native"
    assert parsed["native_helper_path"] == str(helper)
    assert parsed["native_helper_sha256"] == helper_sha


def test_reviewed_hap_carrier_requires_dual_authorization(tmp_path):
    import pytest
    import utilities.dynamic_tester.openharmony_device as module

    with pytest.raises(ValueError, match="execute_carrier"):
        module.OpenHarmonyDeviceConfig(
            serial="fixture-serial",
            carrier_root=str(tmp_path),
            execute_carrier=True,
            allow_state_change=False,
        )


def test_reviewed_hap_carrier_records_marker_impact(tmp_path, monkeypatch):
    from core.exposure_surface import HDCResult
    import utilities.dynamic_tester.openharmony_device as module

    carrier_dir = tmp_path / "carriers" / "OH-DYN-001"
    carrier_dir.mkdir(parents=True)
    hap = carrier_dir / "entry-default-signed.hap"
    hap.write_bytes(b"signed-hap-fixture")
    import hashlib
    hap_sha = hashlib.sha256(hap.read_bytes()).hexdigest()
    (carrier_dir / "manifest.txt").write_text(
        "\n".join([
            "id=OH-DYN-001",
            "mode=udp",
            "host=127.0.0.1",
            "port=8283",
            "local_path=",
            "marker=/data/local/tmp/vf_hap_OH-DYN-001_hack.txt",
            "input_influence_tokens=/data/local/tmp/vf_hap_OH-DYN-001_hack.txt",
            "first=set_pkgName::fixture",
            f"sha256={hap_sha}",
        ]) + "\n",
        encoding="utf-8",
    )
    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)

    class FakeHDC:
        started = False

        def __init__(self, *args, **kwargs):
            pass

        def run_agent(self, command, timeout_seconds=None):
            marker = "/data/local/tmp/vf_hap_OH-DYN-001_hack.txt"
            if command.startswith("aa start"):
                self.started = True
                return HDCResult("agent_command", ("hdc", "shell", command), 0, "start ability successfully\n", "", 1, False)
            if command.startswith("ls -lZ") and self.started:
                return HDCResult("agent_command", ("hdc", "shell", command), 0, f"-rw------- root root {marker}\n", "", 1, False)
            if command.startswith("stat") and self.started:
                return HDCResult("agent_command", ("hdc", "shell", command), 0, "  File: marker\n", "", 1, False)
            if command.startswith("cat") and self.started:
                return HDCResult("agent_command", ("hdc", "shell", command), 0, "hack by nju\n", "", 1, False)
            if command.startswith("rm -f"):
                self.started = False
            return HDCResult("agent_command", ("hdc", "shell", command), 1, "", "No such file\n", 1, False)

    monkeypatch.setattr(module, "HDCClient", FakeHDC)
    monkeypatch.setattr(module, "_run_host", lambda *args: (0, "Install successfully\n", "", 2))
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(
            serial="fixture-serial",
            allow_state_change=True,
            carrier_root=str(tmp_path / "carriers"),
            execute_carrier=True,
            max_commands=64,
        ),
        hdc_path="/tmp/hdc",
    )
    finding = json.loads(pipeline.read_text(encoding="utf-8"))["findings"][0]
    finding["device_artifacts"] = runner._candidate_artifacts(finding)
    result = runner._run_carrier("OH-DYN-001")
    assert result["status"] == "CONFIRMED"
    assert result["verification_level"] == "effect_confirmed"
    assert result["status_reason_code"] == "effect_confirmed"
    # A marker proves an observable effect, but this fixture does not declare
    # that the marker path is bound to a reviewed payload field.  The two
    # claims must stay separate.
    assert result["input_influence"] == "unproven"
    assert result["effect_observed"] is True
    assert result["evidence_ids"]
    assert runner.carrier_specs["OH-DYN-001"]["sha256"] == hap_sha
    assert runner.carrier_specs["OH-DYN-001"]["input_influence_tokens"] == [
        "/data/local/tmp/vf_hap_OH-DYN-001_hack.txt"
    ]
    log_evidence = next(item for item in runner.evidence if item["evidence_id"] == result["log_evidence_id"])
    assert log_evidence["state_change"] is False


def test_protocol_failure_creates_protocol_review_task_without_replaying_hap(tmp_path, monkeypatch):
    """协议类型失败必须转入协议复核，不能原样重放不兼容 HAP。"""

    from core.exposure_surface import HDCResult
    import utilities.dynamic_tester.openharmony_device as module

    carrier_dir = tmp_path / "carriers" / "OH-DYN-001"
    carrier_dir.mkdir(parents=True)
    hap = carrier_dir / "entry-default-signed.hap"
    hap.write_bytes(b"signed-hap-retry-fixture")
    import hashlib
    hap_sha = hashlib.sha256(hap.read_bytes()).hexdigest()
    (carrier_dir / "manifest.txt").write_text(
        "\n".join([
            "id=OH-DYN-001",
            "mode=local",
            "host=",
            "port=0",
            "local_path=/dev/unix/socket/hisysevent",
            "marker=/data/local/tmp/vf_hap_OH-DYN-001_hack.txt",
            f"sha256={hap_sha}",
        ]) + "\n",
        encoding="utf-8",
    )
    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)

    class FakeHDC:
        def __init__(self, *args, **kwargs):
            self.started = False
            self.start_count = 0

        def run_agent(self, command, timeout_seconds=None):
            marker = "/data/local/tmp/vf_hap_OH-DYN-001_hack.txt"
            if command.startswith("aa force-stop"):
                self.started = False
                return HDCResult("agent_command", ("hdc", "shell", command), 0, "stopped\n", "", 1, False)
            if command.startswith("aa start"):
                self.start_count += 1
                self.started = True
                return HDCResult("agent_command", ("hdc", "shell", command), 0, "start ability successfully\n", "", 1, False)
            if command.startswith("hilog") and self.start_count == 1:
                return HDCResult("agent_command", ("hdc", "shell", command), 0, "HAP_POC_FAIL OH-DYN-001: Protocol wrong type for socket\n", "", 1, False)
            if command.startswith("hilog"):
                return HDCResult("agent_command", ("hdc", "shell", command), 0, "HAP_POC_SENT\n", "", 1, False)
            if command.startswith("ls -lZ") and self.started and self.start_count >= 2:
                return HDCResult("agent_command", ("hdc", "shell", command), 0, f"-rw------- root root {marker}\n", "", 1, False)
            if command.startswith("stat") and self.started and self.start_count >= 2:
                return HDCResult("agent_command", ("hdc", "shell", command), 0, "  File: marker\n", "", 1, False)
            if command.startswith("cat /data/local/tmp") and self.started and self.start_count >= 2:
                return HDCResult("agent_command", ("hdc", "shell", command), 0, "hack by nju\n", "", 1, False)
            if command.startswith("cat /proc/net/unix"):
                return HDCResult("agent_command", ("hdc", "shell", command), 0, "Num RefCount Protocol Flags Type St Inode Path\naddr 2 0 0 0002 01 1 /dev/unix/socket/hisysevent\n", "", 1, False)
            if command.startswith("ls -lZ") or command.startswith("stat") or command.startswith("cat /data/local/tmp"):
                return HDCResult("agent_command", ("hdc", "shell", command), 1, "", "No such file\n", 1, False)
            return HDCResult("agent_command", ("hdc", "shell", command), 0, "observed\n", "", 1, False)

    monkeypatch.setattr(module, "HDCClient", FakeHDC)
    monkeypatch.setattr(module, "_run_host", lambda *args: (0, "Install successfully\n", "", 2))
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(
            serial="fixture-serial",
            allow_state_change=True,
            carrier_root=str(tmp_path / "carriers"),
            execute_carrier=True,
            max_commands=64,
        ),
        hdc_path="/tmp/hdc",
    )
    finding = json.loads(pipeline.read_text(encoding="utf-8"))["findings"][0]
    finding["device_artifacts"] = runner._candidate_artifacts(finding)
    first = runner._run_carrier("OH-DYN-001")
    assert first["status"] == "BLOCKED"
    assert first["retryable"] is True
    assert first["retry_reason"] == "protocol_type_mismatch"

    runner._auto_retry_carriers()
    final = runner.carrier_results["OH-DYN-001"]
    assert final["status"] == "BLOCKED"
    assert len(final["attempt_history"]) == 1
    assert final["recovery_task_id"] == "carrier_recovery_OH-DYN-001"
    assert final["recovery_action"] == "protocol_review_required"
    assert final["protocol_review"]["device_facts"]["observed_socket_type"] == "datagram"
    recovery = next(node for node in runner.task_tree["nodes"] if node["task_id"] == "carrier_recovery_OH-DYN-001")
    assert recovery["status"] == "blocked"
    assert final["recovery_evidence_ids"]
    assert runner.hdc.start_count == 1


def test_protocol_fallback_executes_independent_native_artifact_not_original_hap(tmp_path, monkeypatch):
    """协议回退必须切换载体；替代清单中的 HAP 仅用于审计元数据。"""

    import hashlib
    import utilities.dynamic_tester.openharmony_device as module

    carrier_dir = tmp_path / "carriers" / "HV-TEST"
    native_dir = carrier_dir / "alternatives" / "native"
    native_dir.mkdir(parents=True)
    primary_hap = carrier_dir / "entry-default-signed.hap"
    fallback_hap = native_dir / "entry-default-signed.hap"
    helper = native_dir / "vf_native_datagram_sender"
    primary_hap.write_bytes(b"primary-stream-hap")
    fallback_hap.write_bytes(b"audit-copy-only")
    helper.write_bytes(b"reviewed-native-helper")
    fallback_sha = hashlib.sha256(fallback_hap.read_bytes()).hexdigest()
    helper_sha = hashlib.sha256(helper.read_bytes()).hexdigest()
    (carrier_dir / "manifest.txt").write_text(
        "\n".join([
            "id=OH-DYN-001", "mode=local", "host=", "port=0",
            "local_path=/dev/unix/socket/hisysevent",
            "marker=/data/local/tmp/vf_hv_test.txt",
            "sha256=" + hashlib.sha256(primary_hap.read_bytes()).hexdigest(),
        ]) + "\n", encoding="utf-8",
    )
    (native_dir / "manifest.txt").write_text(
        "\n".join([
            "id=OH-DYN-001", "mode=native", "host=", "port=0",
            "local_path=/dev/unix/socket/hisysevent",
            "marker=/data/local/tmp/vf_hv_test.txt",
            "native_helper=vf_native_datagram_sender",
            "native_helper_sha256=" + helper_sha,
            'first={"domain":"AAFWK","stringid":"THREAD_BLOCK_6S","packageName":"hiview"}',
            "sha256=" + fallback_sha,
        ]) + "\n", encoding="utf-8",
    )
    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(
            serial="fixture-serial", allow_state_change=True,
            carrier_root=str(tmp_path / "carriers"), execute_carrier=True,
        ),
        hdc_path="/tmp/hdc",
    )
    runner.carrier_specs["OH-DYN-001"] = {
        "mode": "local",
        "endpoint": {"kind": "local", "path": "/dev/unix/socket/hisysevent"},
        "hap_path": str(primary_hap),
        "sha256": hashlib.sha256(primary_hap.read_bytes()).hexdigest(),
        "carrier_dir": str(carrier_dir),
    }
    runner.carrier_results["OH-DYN-001"] = {
        "status": "BLOCKED", "finding_id": "OH-DYN-001",
        "details": "Protocol wrong type for socket", "retryable": True,
        "retry_reason": "protocol_type_mismatch", "evidence_ids": [],
    }
    monkeypatch.setattr(
        runner,
        "_refresh_carrier_endpoint",
        lambda finding_id: {
            "status": "ok", "finding_id": finding_id, "evidence_ids": [],
            "facts": {"observed_socket_type": "datagram"},
        },
    )

    def fake_run(finding_id, *, force=False, recovery_strategy=None):
        selected = runner.carrier_specs[finding_id]
        assert force is True
        assert recovery_strategy == "protocol_fallback_native"
        assert selected["mode"] == "native"
        assert selected["native_helper_path"] == str(helper)
        assert selected["native_helper_path"] != str(primary_hap)
        result = {
            "status": "NOT_REPRODUCED", "finding_id": finding_id,
            "details": "native path reached", "evidence_ids": [],
            "carrier": selected,
            "carrier_artifact_role": "native_executed_hap_audit_only",
            "executed_artifact": str(helper),
            "executed_artifact_sha256": helper_sha,
            "hap_artifact": str(fallback_hap), "hap_sha256": fallback_sha,
            "native_helper_path": str(helper), "native_helper_sha256": helper_sha,
            "attempt_history": [{
                "attempt": 2, "carrier_mode": "native",
                "carrier_artifact_role": "native_executed_hap_audit_only",
                "executed_artifact": str(helper), "install_performed": False,
            }],
            "retryable": False, "retry_reason": None,
        }
        runner.carrier_attempt_history[finding_id] = result["attempt_history"]
        runner.carrier_results[finding_id] = result
        return result

    monkeypatch.setattr(runner, "_run_carrier", fake_run)
    outcome = runner._review_protocol_failure("OH-DYN-001")
    assert outcome["status"] == "NOT_REPRODUCED"
    assert outcome["operation"] == "fallback_completed"
    final = runner.carrier_results["OH-DYN-001"]
    assert final["carrier_artifact_role"] == "native_executed_hap_audit_only"
    assert final["hap_artifact_role"] == "audit_only"
    assert final["executed_artifact"] == str(helper)
    assert final["hap_artifact"] == str(fallback_hap)
    assert final["attempt_history"][0]["install_performed"] is False
    assert final["protocol_review"]["fallback_selected"]["executed_artifact"] == str(helper)


def test_protocol_preflight_selects_native_before_first_hap_attempt(tmp_path, monkeypatch):
    """已知 SOCK_DGRAM 时，首个载体就应是 Native，而不是先安装 Stream HAP。"""

    import hashlib
    import utilities.dynamic_tester.openharmony_device as module

    carrier_dir = tmp_path / "carriers" / "OH-DYN-001"
    native_dir = carrier_dir / "alternatives" / "native"
    native_dir.mkdir(parents=True)
    primary_hap = carrier_dir / "entry-default-signed.hap"
    fallback_hap = native_dir / "entry-default-signed.hap"
    helper = native_dir / "vf_native_datagram_sender"
    primary_hap.write_bytes(b"primary-stream-hap")
    fallback_hap.write_bytes(b"audit-copy-only")
    helper.write_bytes(b"reviewed-native-helper")
    fallback_sha = hashlib.sha256(fallback_hap.read_bytes()).hexdigest()
    helper_sha = hashlib.sha256(helper.read_bytes()).hexdigest()
    (native_dir / "manifest.txt").write_text(
        "\n".join([
            "id=OH-DYN-001", "mode=native", "host=", "port=0",
            "local_path=/dev/unix/socket/hisysevent",
            "marker=/data/local/tmp/vf_hv_test.txt",
            "native_helper=vf_native_datagram_sender",
            "native_helper_sha256=" + helper_sha,
            "sha256=" + fallback_sha,
        ]) + "\n", encoding="utf-8",
    )
    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(
            serial="fixture-serial", allow_state_change=True,
            carrier_root=str(tmp_path / "carriers"), execute_carrier=True,
        ),
        hdc_path="/tmp/hdc",
    )
    runner.carrier_specs["OH-DYN-001"] = {
        "mode": "local",
        "endpoint": {"kind": "local", "path": "/dev/unix/socket/hisysevent"},
        "hap_path": str(primary_hap),
        "sha256": hashlib.sha256(primary_hap.read_bytes()).hexdigest(),
        "carrier_dir": str(carrier_dir),
    }
    monkeypatch.setattr(
        runner,
        "_refresh_carrier_endpoint",
        lambda finding_id: {
            "status": "ok", "finding_id": finding_id, "evidence_ids": ["OHDEV-EV-0001"],
            "facts": {"observed_socket_type": "datagram", "observed_socket_type_code": "0002"},
        },
    )

    review = runner._preflight_protocol_carrier("OH-DYN-001")
    assert review["status"] == "selected"
    selected = runner.carrier_specs["OH-DYN-001"]
    assert selected["mode"] == "native"
    assert selected["native_helper_path"] == str(helper)
    assert selected["native_helper_path"] != str(primary_hap)
    assert selected["primary_hap_artifact"] == str(primary_hap)
    assert selected["protocol_selection"] == "preflight_native"
    assert runner.carrier_preflight_reviews["OH-DYN-001"]["selected_mode"] == "native"


def test_review_preconditions_refreshes_facts_without_replaying_carrier(tmp_path, monkeypatch):
    """补证策略只刷新事实并更新任务树，不重复发送同一载体。"""

    import utilities.dynamic_tester.openharmony_device as module

    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(serial="fixture-serial"),
        hdc_path="/tmp/hdc",
    )
    runner.carrier_results["OH-DYN-001"] = {
        "status": "NOT_REPRODUCED",
        "finding_id": "OH-DYN-001",
        "status_reason_code": "service_path_reached_input_unproven",
        "details": "服务路径已达",
        "evidence_ids": [],
        "retryable": False,
    }
    monkeypatch.setattr(
        runner,
        "_refresh_carrier_endpoint",
        lambda finding_id: {
            "status": "ok",
            "finding_id": finding_id,
            "facts": {"observed_socket_type": "stream"},
            "evidence_ids": [],
        },
    )
    replayed = []
    monkeypatch.setattr(runner, "_run_carrier", lambda *args, **kwargs: replayed.append(args) or {})

    result = runner._retry_carrier("OH-DYN-001", "review_preconditions")

    assert result["operation"] == "preconditions_reviewed"
    assert result["recovery_action"] == "preconditions_reviewed_no_replay"
    assert result["precondition_review"]["facts"]["observed_socket_type"] == "stream"
    assert replayed == []
    node = next(
        node for node in runner.task_tree["nodes"]
        if node["task_id"] == "carrier_observation_OH-DYN-001_service_path_reached_input_unproven"
    )
    assert node["status"] == "completed"


def test_protocol_fallback_execution_layer_rejects_original_hap(tmp_path):
    """即使调用方误传旧载体，执行层也不能把它当第二次自适应尝试。"""

    import utilities.dynamic_tester.openharmony_device as module

    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(
            serial="fixture-serial", allow_state_change=True,
            execute_carrier=True, carrier_root=str(tmp_path / "carriers"),
        ),
        hdc_path="/tmp/hdc",
    )
    runner.carrier_specs["OH-DYN-001"] = {
        "mode": "local",
        "endpoint": {"kind": "local", "path": "/dev/unix/socket/hisysevent"},
        "hap_path": str(tmp_path / "entry-default-signed.hap"),
        "sha256": "reviewed-hap-sha",
        "marker": "/data/local/tmp/vf_test_marker",
        "carrier_bundle": "com.security.research.trigger",
        "carrier_ability": "EntryAbility",
    }
    outcome = runner._run_carrier(
        "OH-DYN-001", force=True, recovery_strategy="protocol_fallback_native"
    )
    assert outcome["status"] == "BLOCKED"
    assert outcome["reason"] == "protocol_fallback_requires_native_carrier"
    assert outcome["carrier_artifact_role"] == "not_executed"
    assert runner.commands == []


def test_materialized_results_expose_fallback_artifact_identity(tmp_path):
    """旧版结果查看器也必须能看出 native 回退没有重装原 HAP。"""

    import utilities.dynamic_tester.openharmony_device as module

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    summary = {
        "run_id": "fixture-run",
        "run_dir": str(run_dir),
        # Deliberately stale aggregate: projection must recompute it from the
        # per-finding decisions instead of copying this value.
        "status_counts": {"NOT_REPRODUCED": 99},
        "results": [{
            "finding_id": "HV-02",
            "status": "NOT_REPRODUCED",
            "details": "服务路径已触达，但未观察到 canary。",
            "evidence_ids": [],
        }],
            "carrier_results": {
            "HV-02": {
                "status": "NOT_REPRODUCED",
                "verification_level": "input_influence_proven",
                "status_reason_code": "input_influence_proven_effect_absent",
                "input_influence": "proven",
                "input_influence_proven": True,
                "input_echo_proven": True,
                "payload_echo_observed": True,
                "payload_echo_dangerous_parameter": True,
                "payload_echo_scope": "dangerous_parameter",
                "observed_effect_kind": "input_influence",
                "carrier_artifact_role": "native_executed_hap_audit_only",
                "executed_artifact": "/tmp/vf_native_datagram_sender",
                "executed_artifact_sha256": "helper-sha",
                "hap_artifact": "/tmp/entry-default-signed.hap",
                "hap_sha256": "hap-sha",
                "native_helper_path": "/tmp/vf_native_datagram_sender",
                "native_helper_sha256": "helper-sha",
                "attempt_history": [
                    {"attempt": 1, "carrier_mode": "local", "status": "BLOCKED", "install_performed": True},
                    {"attempt": 2, "carrier_mode": "native", "status": "NOT_REPRODUCED", "install_performed": False},
                ],
                "protocol_review": {
                    "device_facts": {"observed_socket_type": "datagram"},
                    "fallback_selected": {"mode": "native", "executed_artifact": "/tmp/vf_native_datagram_sender"},
                },
            },
        },
    }
    (tmp_path / "out").mkdir()
    json_path, md_path, results = module.materialize_dynamic_results(summary, str(tmp_path / "out"))
    artifacts = results[0].artifacts
    assert artifacts["carrier.carrier_artifact_role"] == "native_executed_hap_audit_only"
    assert artifacts["carrier.hap_artifact_role"] == "audit_only"
    assert artifacts["carrier.executed_artifact"] == "/tmp/vf_native_datagram_sender"
    assert artifacts["carrier.install_performed"] == "attempt_1=true;attempt_2=false"
    assert artifacts["carrier.install_any_attempt"] == "True"
    report = Path(md_path).read_text(encoding="utf-8")
    assert "载体执行与回退审计" in report
    assert "首次 HAP 尝试" in report
    assert "仅审计 HAP（未执行）" in report
    assert "没有再次安装原始 Stream HAP" in report
    payload = json.loads(Path(json_path).read_text(encoding="utf-8"))
    assert payload["results"][0]["artifacts"]["carrier.executed_artifact"] == "/tmp/vf_native_datagram_sender"
    assert payload["status_counts"] == {"NOT_REPRODUCED": 1}
    observation = payload["results"][0]["observation"]
    assert observation["verification_level"] == "input_influence_proven"
    assert observation["input_influence_proven"] is True
    assert observation["payload_echo_scope"] == "dangerous_parameter"


def test_materialized_results_reclassify_legacy_service_path_as_inconclusive(tmp_path):
    """旧产物的路径命中不能继续伪装成“已证明未复现”。"""

    import utilities.dynamic_tester.openharmony_device as module

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    summary = {
        "run_id": "legacy-path-run",
        "run_dir": str(run_dir),
        "results": [{
            "finding_id": "LEGACY-01",
            "status": "NOT_REPRODUCED",
            "details": "旧版本：目标服务路径已触达。",
            "evidence_ids": [],
        }],
        "carrier_results": {
            "LEGACY-01": {
                "status": "NOT_REPRODUCED",
                "verification_level": "service_path_reached",
                "status_reason_code": "service_path_reached_input_unproven",
                "observed_effect_kind": "service_path",
                "expected_effect": "marker",
                "target_reached": True,
                "sink_reached": False,
                "input_influence_proven": False,
                "payload_echo_observed": False,
                "effect_observed": False,
                "precondition_status": "not_declared",
            },
        },
    }
    (tmp_path / "out").mkdir()
    json_path, _md_path, results = module.materialize_dynamic_results(
        summary, str(tmp_path / "out")
    )
    assert results[0].status == "INCONCLUSIVE"
    payload = json.loads(Path(json_path).read_text(encoding="utf-8"))
    assert payload["status_counts"] == {"INCONCLUSIVE": 1}
    assert payload["results"][0]["observation"]["status_reason_code"] == (
        "service_path_reached_input_unproven"
    )


def test_stale_hilog_failure_is_not_attributed_to_current_finding(tmp_path):
    """上一样本的协议错误不能污染当前已发送请求的样本结论。"""

    import utilities.dynamic_tester.openharmony_device as module

    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    stale_log = {
        "returncode": 0,
        "stdout": (
            "HAP_POC_FAIL HV-02: Protocol wrong type for socket\n"
            "HAP_POC_START DP-03 mode=udp\n"
            "HAP_POC_SENT DP-03 transport=udp marker=/data/local/tmp/x\n"
        ),
        "stderr": "",
    }
    assert module.OpenHarmonyDeviceRunner._classify_carrier_failure(
        stale_log,
        finding_id="DP-03",
        install_rc=0,
        start_rc=0,
        mode="udp",
        marker_match=False,
    ) is None

    current_fail = {
        "returncode": 0,
        "stdout": "HAP_POC_FAIL HV-02: Protocol wrong type for socket\n",
        "stderr": "",
    }
    assert module.OpenHarmonyDeviceRunner._classify_carrier_failure(
        current_fail,
        finding_id="HV-02",
        install_rc=0,
        start_rc=0,
        mode="local",
        marker_match=False,
    ) == "protocol_type_mismatch"

    generic_fail = {
        "returncode": 0,
        "stdout": "HAP_POC_FAIL DP-11: Operation in progress\n",
        "stderr": "",
    }
    assert module.OpenHarmonyDeviceRunner._classify_carrier_failure(
        generic_fail,
        finding_id="DP-11",
        install_rc=0,
        start_rc=0,
        mode="tcp",
        marker_match=False,
    ) == "service_busy"

    # 同一个 finding 的历史失败也不能污染本次已经发送成功的尝试。
    # hilog 是持久 ring buffer，不能用“日志中出现过 FAIL”替代按时间顺序
    # 选择本次最新的样本标记。
    same_finding_old_fail_then_sent = {
        "returncode": 0,
        "stdout": (
            "HAP_POC_FAIL DP-11: Operation in progress\n"
            "HAP_POC_START DP-11 mode=tcp\n"
            "HAP_POC_SENT DP-11 transport=tcp\n"
        ),
        "stderr": "",
    }
    assert module.OpenHarmonyDeviceRunner._classify_carrier_failure(
        same_finding_old_fail_then_sent,
        finding_id="DP-11",
        install_rc=0,
        start_rc=0,
        mode="tcp",
        marker_match=False,
    ) is None


def test_service_crash_manifest_and_pid_snapshot_are_explicit():
    import utilities.dynamic_tester.openharmony_device as module

    assert module.OpenHarmonyDeviceRunner._pid_list({
        "returncode": 0,
        "stdout": "123 456\n",
        "stderr": "",
    }) == ["123", "456"]
    assert module.OpenHarmonyDeviceRunner._pid_list({
        "returncode": 1,
        "stdout": "123\n",
        "stderr": "not found",
    }) == []

    assert module._SERVICE_PROCESS_RE.fullmatch("SP_daemon")
    assert not module._SERVICE_PROCESS_RE.fullmatch("SP_daemon;rm -rf /")


def test_transient_failure_retries_same_reviewed_carrier_once(tmp_path, monkeypatch):
    """连接/超时类瞬时失败可以刷新证据后重试同一份已核验载体。"""

    import utilities.dynamic_tester.openharmony_device as module

    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(
            serial="fixture-serial", allow_state_change=True,
            carrier_root=str(tmp_path), execute_carrier=True,
        ),
        hdc_path="/tmp/hdc",
    )
    runner.carrier_specs["OH-DYN-001"] = {"mode": "udp", "endpoint": {"kind": "udp", "host": "127.0.0.1", "port": 8283}}
    runner.carrier_attempt_history["OH-DYN-001"] = [{
        "attempt": 1, "status": "BLOCKED", "details": "连接被拒绝",
        "evidence_ids": [], "retryable": True, "retry_reason": "endpoint_connection_refused",
        "recovery_strategy": None,
    }]
    runner.carrier_results["OH-DYN-001"] = {
        "status": "BLOCKED", "finding_id": "OH-DYN-001", "details": "连接被拒绝",
        "evidence_ids": [], "retryable": True, "retry_reason": "endpoint_connection_refused",
    }
    refreshed = {"status": "ok", "evidence_ids": [], "facts": {"declared_mode": "udp"}}
    monkeypatch.setattr(runner, "_refresh_carrier_endpoint", lambda finding_id: refreshed)

    def fake_run(finding_id, *, force=False, recovery_strategy=None):
        assert force is True
        assert recovery_strategy == "refresh_endpoint"
        result = {
            "status": "CONFIRMED", "finding_id": finding_id, "details": "第二次载体执行形成决定性证据",
            "evidence_ids": [], "retryable": False, "retry_reason": None,
        }
        runner.carrier_attempt_history[finding_id].append({
            "attempt": 2, "status": "CONFIRMED", "details": result["details"],
            "evidence_ids": [], "retryable": False, "retry_reason": None,
            "recovery_strategy": recovery_strategy,
        })
        result["attempt_history"] = list(runner.carrier_attempt_history[finding_id])
        return result

    monkeypatch.setattr(runner, "_run_carrier", fake_run)
    outcome = runner._retry_carrier("OH-DYN-001")
    assert outcome["operation"] == "retried"
    assert outcome["status"] == "CONFIRMED"
    assert runner.carrier_results["OH-DYN-001"]["status"] == "CONFIRMED"
    assert len(runner.carrier_results["OH-DYN-001"]["attempt_history"]) == 2
    assert runner.carrier_results["OH-DYN-001"]["recovery_task_id"] == "carrier_recovery_OH-DYN-001"


def test_review_preconditions_refreshes_facts_without_replaying_carrier(tmp_path, monkeypatch):
    """路径已达但影响未证实时，复核前置条件不应再次发送同一载体。"""

    import utilities.dynamic_tester.openharmony_device as module

    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(serial="fixture-serial"),
        hdc_path="/tmp/hdc",
    )
    runner.carrier_specs["OH-DYN-001"] = {
        "mode": "udp",
        "endpoint": {"kind": "udp", "host": "127.0.0.1", "port": 8283},
    }
    runner.carrier_results["OH-DYN-001"] = {
        "status": "NOT_REPRODUCED",
        "finding_id": "OH-DYN-001",
        "status_reason_code": "service_path_reached_input_unproven",
        "target_reached": True,
        "retryable": False,
        "evidence_ids": [],
    }
    monkeypatch.setattr(
        runner,
        "_refresh_carrier_endpoint",
        lambda finding_id: {
            "status": "ok",
            "facts": {"declared_mode": "udp", "observed_protocols": ["udp"]},
            "evidence_ids": [],
        },
    )
    outcome = runner._retry_carrier("OH-DYN-001", "review_preconditions")
    assert outcome["operation"] == "preconditions_reviewed"
    assert outcome["recovery_action"] == "preconditions_reviewed_no_replay"
    assert outcome["precondition_review"]["facts"]["observed_protocols"] == ["udp"]
    assert runner.carrier_attempt_history.get("OH-DYN-001", []) == []


def test_reviewed_cli_carrier_is_separate_from_normal_cli_grammar(tmp_path):
    """命令行注入样本只能使用固定清单载体，普通 CLI 规则仍保持无元字符。"""

    import hashlib
    import pytest
    import utilities.dynamic_tester.openharmony_device as module

    carrier = tmp_path / "DP-17"
    carrier.mkdir()
    hap = carrier / "entry-default-signed.hap"
    hap.write_bytes(b"fixture-cli-hap")
    sha = hashlib.sha256(hap.read_bytes()).hexdigest()
    (carrier / "manifest.txt").write_text(
        "\n".join([
            "id=DP-17",
            "mode=cli_reviewed",
            "host=",
            "port=0",
            "local_path=",
            "marker=/data/local/tmp/vf_dynamic_dp17_data.csv",
            "command=/system/bin/SP_daemon -N 1 -PID 602 -OUT \"/data/local/tmp/vf_dynamic_dp17_data.csv;echo 'hack by nju' > /data/local/tmp/vf_dynamic_dp17_data.csv;#\"",
            f"sha256={sha}",
        ]) + "\n",
        encoding="utf-8",
    )
    parsed = module._parse_carrier_manifest(carrier / "manifest.txt", hap, "DP-17")
    assert parsed["mode"] == "cli_reviewed"
    assert parsed["endpoint"]["kind"] == "cli_reviewed"
    assert "hack by nju" in parsed["command"]

    # Changing even the fixed canary text must fail closed; this prevents the
    # model/runtime from turning the reviewed mode into an arbitrary shell.
    (carrier / "manifest.txt").write_text(
        (carrier / "manifest.txt").read_text(encoding="utf-8").replace("hack by nju", "other-command"),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="cli_reviewed"):
        module._parse_carrier_manifest(carrier / "manifest.txt", hap, "DP-17")


def test_cli_business_error_is_not_treated_as_clean_non_reproduction():
    """设备程序拒绝参数时，HDC 外层 0 不能掩盖载体能力不匹配。"""

    import utilities.dynamic_tester.openharmony_device as module

    rejected = "SP_daemon:invalid parameter -- 'HCI'\nUsage: SP_daemon [options]"
    assert module._CLI_CARRIER_BUSINESS_ERROR_RE.search(rejected)
    assert module._CLI_CARRIER_BUSINESS_ERROR_RE.search("command exec finished!") is None


def test_carrier_manifest_accepts_risk_profile_and_preconditions(tmp_path):
    """清单可以声明风险/前置条件，但仍保持受限载体校验。"""

    import hashlib
    import utilities.dynamic_tester.openharmony_device as module

    carrier = tmp_path / "DP-PROFILE"
    carrier.mkdir()
    hap = carrier / "entry-default-signed.hap"
    hap.write_bytes(b"profile-hap")
    sha = hashlib.sha256(hap.read_bytes()).hexdigest()
    (carrier / "manifest.txt").write_text(
        "\n".join([
            "id=DP-PROFILE",
            "mode=udp",
            "host=127.0.0.1",
            "port=8283",
            "local_path=",
            "marker=/data/local/tmp/vf_profile_marker.txt",
            "risk_type=command_injection",
            "expected_effect=marker",
            "precondition=先设置共享状态，再发送触发消息",
            "required_service=SP_daemon",
            "required_socket_type=datagram",
            "sink_log_tokens=LoadCmd,popen",
            f"sha256={sha}",
        ]) + "\n",
        encoding="utf-8",
    )
    parsed = module._parse_carrier_manifest(carrier / "manifest.txt", hap, "DP-PROFILE")
    assert parsed["risk_type"] == "command_injection"
    assert parsed["precondition"] == "先设置共享状态，再发送触发消息"
    assert parsed["required_service"] == "SP_daemon"
    assert parsed["required_socket_type"] == "datagram"
    assert parsed["sink_log_tokens"] == ["LoadCmd", "popen"]


def test_payload_bound_canary_requires_reviewed_payload_binding(tmp_path):
    """payload-bound canary 只能由清单显式声明且必须出现在载荷中。"""

    import hashlib
    import pytest
    import utilities.dynamic_tester.openharmony_device as module

    carrier = tmp_path / "BOUND"
    carrier.mkdir()
    hap = carrier / "entry-default-signed.hap"
    hap.write_bytes(b"bound-hap")
    sha = hashlib.sha256(hap.read_bytes()).hexdigest()
    base = [
        "id=BOUND",
        "mode=udp",
        "host=127.0.0.1",
        "port=8283",
        "local_path=",
        "marker=/data/local/tmp/vf_bound.txt",
        "canary_binding=payload_path",
        f"sha256={sha}",
    ]
    (carrier / "manifest.txt").write_text("\n".join(base) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="marker 出现在"):
        module._parse_carrier_manifest(carrier / "manifest.txt", hap, "BOUND")

    (carrier / "manifest.txt").write_text(
        "\n".join(base + [
            "first=set_pkgName::/data/local/tmp/vf_bound.txt",
            "payload_echo_tokens=vf_bound.txt",
        ]) + "\n",
        encoding="utf-8",
    )
    parsed = module._parse_carrier_manifest(carrier / "manifest.txt", hap, "BOUND")
    assert parsed["canary_binding"] == "payload_path"
    assert parsed["payload_echo_tokens"] == ["vf_bound.txt"]

    (carrier / "manifest.txt").write_text(
        "\n".join(base[:7] + [
            "canary_binding=payload_echo",
            "first=set_pkgName::/data/local/tmp/vf_bound.txt",
            "payload_echo_tokens=vf_bound.txt",
            f"sha256={sha}",
        ]) + "\n",
        encoding="utf-8",
    )
    parsed_echo = module._parse_carrier_manifest(carrier / "manifest.txt", hap, "BOUND")
    assert parsed_echo["canary_binding"] == "payload_echo"


def test_payload_echo_is_not_security_effect_without_canary():
    import utilities.dynamic_tester.openharmony_device as module

    echoed = module._classify_observed_effect(
        expected_effect="marker",
        marker_match=False,
        service_crash_observed=False,
        artifact_created=False,
        target_reached=True,
        carrier_sent=True,
        payload_echo_observed=True,
    )
    assert echoed["status"] == "INCONCLUSIVE"
    assert echoed["verification_level"] == "payload_echo_observed"
    assert echoed["input_influence"] == "proven"
    assert echoed["input_echo_proven"] is True


def test_dangerous_parameter_echo_proves_input_influence_but_not_effect():
    import utilities.dynamic_tester.openharmony_device as module

    echoed = module._classify_observed_effect(
        expected_effect="marker",
        marker_match=False,
        service_crash_observed=False,
        artifact_created=False,
        target_reached=True,
        carrier_sent=True,
        payload_echo_observed=True,
        payload_echo_dangerous_parameter=True,
    )
    assert echoed["status"] == "NOT_REPRODUCED"
    assert echoed["verification_level"] == "input_influence_proven"
    assert echoed["observed_effect_kind"] == "input_influence"
    assert echoed["input_influence"] == "proven"
    assert echoed["input_echo_proven"] is True


def test_payload_echo_scope_requires_reviewed_echo_tokens(tmp_path):
    import hashlib
    import pytest
    import utilities.dynamic_tester.openharmony_device as module

    carrier = tmp_path / "ECHO-SCOPE"
    carrier.mkdir()
    hap = carrier / "entry-default-signed.hap"
    hap.write_bytes(b"echo-scope-hap")
    sha = hashlib.sha256(hap.read_bytes()).hexdigest()
    base = [
        "id=ECHO-SCOPE",
        "mode=udp",
        "host=127.0.0.1",
        "port=8283",
        "local_path=",
        "marker=/data/local/tmp/vf_echo_scope.txt",
        "payload_echo_scope=dangerous_parameter",
        f"sha256={sha}",
    ]
    (carrier / "manifest.txt").write_text("\n".join(base) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="payload_echo_tokens"):
        module._parse_carrier_manifest(carrier / "manifest.txt", hap, "ECHO-SCOPE")
    (carrier / "manifest.txt").write_text(
        "\n".join(base + [
            "first=payload-echo-token",
            "payload_echo_tokens=payload-echo-token",
        ]) + "\n",
        encoding="utf-8",
    )
    parsed = module._parse_carrier_manifest(carrier / "manifest.txt", hap, "ECHO-SCOPE")
    assert parsed["payload_echo_scope"] == "dangerous_parameter"


def test_merge_log_observations_keeps_primary_and_delayed_evidence():
    import utilities.dynamic_tester.openharmony_device as module

    merged = module.OpenHarmonyDeviceRunner._merge_log_observations(
        {"stdout": "first", "stderr": "", "returncode": 0, "evidence_id": "E1"},
        {"stdout": "second", "stderr": "late", "returncode": 0, "evidence_id": "E2"},
    )
    assert merged["stdout"] == "first\nsecond"
    assert merged["stderr"] == "late"
    assert merged["evidence_id"] == "E1"
    assert merged["followup_evidence_id"] == "E2"


def test_carrier_observation_tokens_merge_all_reviewed_fields():
    import utilities.dynamic_tester.openharmony_device as module

    assert module.OpenHarmonyDeviceRunner._carrier_observation_tokens({
        "target_log_tokens": ["target", "same"],
        "sink_log_tokens": ["sink", "same"],
        "input_influence_tokens": ["input"],
        "payload_echo_tokens": ["echo", "sink"],
    }) == ["target", "same", "sink", "input", "echo"]


def test_target_log_evidence_excludes_carrier_self_report():
    import utilities.dynamic_tester.openharmony_device as module

    evidence = module.OpenHarmonyDeviceRunner._target_log_evidence(
        {
            "stdout": (
                "HAP_POC_SENT BOUND transport=udp marker=/data/local/tmp/vf_bound.txt\n"
                "08-04 21:05:54 HDC_LOG: ExecuteCommand cmd:cat /data/local/tmp/vf_bound.txt\n"
                "service sink=/data/local/tmp/vf_bound.txt\n"
            ),
            "stderr": "",
        },
        finding_id="BOUND",
        tokens=["vf_bound.txt"],
    )
    assert evidence["reached"] is True
    assert evidence["matches"] == ["service sink=/data/local/tmp/vf_bound.txt"]


def test_observation_classifier_separates_service_path_from_input_effect():
    """触及服务但没有 canary 时必须保留“输入影响未证实”状态。"""

    import utilities.dynamic_tester.openharmony_device as module

    path_only = module._classify_observed_effect(
        expected_effect="marker",
        marker_match=False,
        service_crash_observed=False,
        artifact_created=False,
        target_reached=True,
        carrier_sent=True,
    )
    assert path_only["status"] == "INCONCLUSIVE"
    assert path_only["verification_level"] == "service_path_reached"
    assert path_only["status_reason_code"] == "service_path_reached_input_unproven"
    assert path_only["input_influence"] == "unproven"
    assert path_only["effect_observed"] is False


def test_observation_classifier_confirms_only_decisive_effects():
    """canary/崩溃是决定性效果；普通业务产物不能冒充安全影响。"""

    import utilities.dynamic_tester.openharmony_device as module

    marker = module._classify_observed_effect(
        expected_effect="marker",
        marker_match=True,
        service_crash_observed=False,
        artifact_created=False,
        target_reached=True,
        carrier_sent=True,
    )
    assert marker["status"] == "CONFIRMED"
    assert marker["verification_level"] == "effect_confirmed"
    assert marker["input_influence"] == "unproven"
    assert marker["effect_observed"] is True

    bound_marker = module._classify_observed_effect(
        expected_effect="marker",
        marker_match=True,
        service_crash_observed=False,
        artifact_created=False,
        target_reached=True,
        carrier_sent=True,
        input_influence_proven=True,
    )
    assert bound_marker["status"] == "CONFIRMED"
    assert bound_marker["input_influence"] == "proven"

    artifact = module._classify_observed_effect(
        expected_effect="service_artifact",
        marker_match=False,
        service_crash_observed=False,
        artifact_created=True,
        target_reached=True,
        carrier_sent=True,
    )
    assert artifact["status"] == "INCONCLUSIVE"
    assert artifact["verification_level"] == "service_artifact_observed"
    assert artifact["status_reason_code"] == "artifact_observed_no_canary"
    assert artifact["effect_observed"] is True
    assert artifact["input_influence"] == "unproven"


def test_observation_classifier_records_effect_kind_without_upgrading_path_only():
    import utilities.dynamic_tester.openharmony_device as module

    path_only = module._classify_observed_effect(
        expected_effect="marker",
        marker_match=False,
        service_crash_observed=False,
        artifact_created=False,
        target_reached=True,
        carrier_sent=True,
    )
    assert path_only["observed_effect_kind"] == "service_path"

    crash = module._classify_observed_effect(
        expected_effect="service_crash",
        marker_match=False,
        service_crash_observed=True,
        artifact_created=False,
        target_reached=True,
        carrier_sent=True,
    )
    assert crash["observed_effect_kind"] == "service_crash"


def test_summarize_verdicts_keeps_status_and_evidence_dimensions_separate():
    import utilities.dynamic_tester.openharmony_device as module

    summary = module._summarize_verdicts([
        {
            "status": "CONFIRMED",
            "verification_level": "effect_confirmed",
            "status_reason_code": "effect_confirmed",
            "observed_effect_kind": "marker",
        },
        {
            "status": "INCONCLUSIVE",
            "verification_level": "service_path_reached",
            "status_reason_code": "service_path_reached_input_unproven",
            "observed_effect_kind": "service_path",
        },
    ])
    assert summary["status_counts"] == {"CONFIRMED": 1, "INCONCLUSIVE": 1}
    assert summary["verification_level_counts"]["service_path_reached"] == 1
    assert summary["effect_kind_counts"] == {"marker": 1, "service_path": 1}


def test_summarize_verdicts_exposes_input_evidence_layers():
    import utilities.dynamic_tester.openharmony_device as module

    summary = module._summarize_verdicts([
        {"input_influence_proven": True},
        {"input_echo_proven": True},
        {"target_reached": True},
        {},
    ])
    assert summary["input_evidence_counts"] == {
        "dangerous_parameter_proven": 1,
        "service_echo_proven": 1,
        "service_path_input_unproven": 1,
        "no_input_evidence": 1,
    }


def test_service_crash_expected_effect_needs_process_evidence():
    import utilities.dynamic_tester.openharmony_device as module

    no_crash = module._classify_observed_effect(
        expected_effect="service_crash",
        marker_match=False,
        service_crash_observed=False,
        artifact_created=False,
        target_reached=True,
        carrier_sent=True,
    )
    assert no_crash["status"] == "INCONCLUSIVE"
    assert no_crash["status_reason_code"] == "service_path_reached_input_unproven"

    crash = module._classify_observed_effect(
        expected_effect="service_crash",
        marker_match=False,
        service_crash_observed=True,
        artifact_created=False,
        target_reached=True,
        carrier_sent=True,
    )
    assert crash["status"] == "CONFIRMED"
    assert crash["verification_level"] == "effect_confirmed"


def test_cli_preflight_records_device_capabilities(tmp_path, monkeypatch):
    """存在 CLI 载体时，预检应留下版本能力证据而非事后猜测。"""

    from core.exposure_surface import HDCResult
    import utilities.dynamic_tester.openharmony_device as module

    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)
    class FakeHDC:
        def run_agent(self, command, timeout_seconds=None):
            output = "Usage: SP_daemon [-N] [-PID] [-ci] [-OUT]\n" if "--help" in command else "ok\n"
            return HDCResult("agent_command", ("hdc", "shell", command), 0, output, "", 1, False)

    monkeypatch.setattr(module, "HDCClient", lambda *args, **kwargs: FakeHDC())
    runner = module.OpenHarmonyDeviceRunner(
        str(pipeline), str(tmp_path / "out"),
        config=module.OpenHarmonyDeviceConfig(serial="fixture-serial"),
        hdc_path="/tmp/hdc",
    )
    runner.carrier_specs["OH-DYN-001"] = {"mode": "cli", "endpoint": {"kind": "cli"}}
    preflight = runner._preflight()
    assert preflight["capabilities"]["SP_daemon"]["status"] == "available"
    assert "-ci" in preflight["capabilities"]["SP_daemon"]["options"]
    assert preflight["capabilities"]["SP_daemon"]["evidence_id"]
