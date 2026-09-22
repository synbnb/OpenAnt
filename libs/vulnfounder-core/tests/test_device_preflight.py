"""L0 设备前置确认的纯解析与假 HDC 测试。"""

from __future__ import annotations

from types import SimpleNamespace

from utilities.openharmony_dynamic.device_preflight import (
    MISMATCH,
    MATCHED,
    SERVICE_UNAVAILABLE,
    VERSION_UNVERIFIED,
    collect_device_fingerprint,
    parse_proc_net_table,
    parse_proc_net_unix,
    parse_ps,
)


def test_parse_socket_tables_and_states():
    tcp = parse_proc_net_table(
        "  sl  local_address rem_address   st\n"
        "   0: 0100007F:205B 00000000:0000 0A 00000000\n", "tcp"
    )
    assert tcp[0]["endpoint"] == "127.0.0.1:8283"
    assert tcp[0]["state"] == "LISTENING"
    udp = parse_proc_net_table(
        "  sl  local_address rem_address   st\n"
        "   0: 0100007F:205D 00000000:0000 07 00000000\n", "udp"
    )
    assert udp[0]["endpoint"] == "127.0.0.1:8285"
    assert udp[0]["state"] == "BOUND"


def test_parse_unix_and_process_tables():
    unix = parse_proc_net_unix(
        "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "00000000: 00000002 00000000 00010000 0001 01 12345 /dev/unix/socket/example\n"
    )
    assert unix[0]["path"] == "/dev/unix/socket/example"
    assert unix[0]["named"] is True
    rows = parse_ps("UID PID PPID CMD\nroot 1 0 init\nroot 42 1 service_daemon\n")
    assert {row["name"] for row in rows} == {"init", "service_daemon"}


class _FakeHDC:
    serial = "BOARD-202609220001"

    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []

    def shell(self, argv, *, purpose="", **_kwargs):
        key = argv[-1] if argv else ""
        self.calls.append((argv, purpose))
        output = self.outputs.get(key, self.outputs.get("default", ""))
        return SimpleNamespace(returncode=0, stdout=output, stderr="")


def test_collect_fingerprint_distinguishes_version_and_service_state():
    outputs = {
        "getprop": "[ro.build.version.release]: [6.1]\n",
        "uname": "OpenHarmony test\n",
        "id": "uid=0(root) gid=0(root)\n",
        "ps": "UID PID PPID CMD\nroot 42 1 service_daemon\n",
        "-A": "UID PID PPID CMD\nroot 42 1 service_daemon\n",
        "/proc/net/unix": "Num RefCount Protocol Flags Type St Inode Path\n"
        "0: 2 0 10000 1 01 1 /dev/unix/socket/example\n",
        "/proc/net/tcp": "sl local rem st\n0: 0100007F:205B 00000000:0 0A\n",
        "/proc/net/tcp6": "",
        "/proc/net/udp": "",
        "/proc/net/udp6": "",
        "/proc/42/attr/current": "u:r:service:s0\n",
        "/proc/42/exe": "/system/bin/service_daemon\n",
        "/system/bin/service_daemon": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  /system/bin/service_daemon\n",
    }
    fake = _FakeHDC(outputs)
    fp = collect_device_fingerprint(
        fake,
        targets=["/dev/unix/socket/example", "127.0.0.1:8283"],
        process_names=["service_daemon"],
        source_revision="source-1",
        reference={"source_revision": "source-1"},
    )
    assert fp.status == MATCHED
    assert fp.services[0].present is True
    assert fp.services[1].present is True
    assert fp.device_revision == "6.1"
    process_service = next(item for item in fp.services if item.kind == "process")
    assert process_service.binary_path == "/system/bin/service_daemon"
    assert process_service.binary_sha256 == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    assert fp.service_health["status"] == "READY"
    assert fp.service_health["ready"] is True

    missing = _FakeHDC(outputs)
    fp2 = collect_device_fingerprint(
        missing,
        targets=["/dev/unix/socket/not-present"],
        source_revision="source-1",
        reference={"source_revision": "source-1"},
    )
    assert fp2.status == SERVICE_UNAVAILABLE
    assert fp2.service_health["status"] == "NOT_READY"

    unknown = _FakeHDC(outputs)
    fp3 = collect_device_fingerprint(unknown, targets=[])
    assert fp3.status == VERSION_UNVERIFIED


def test_reference_binary_and_system_facts_are_compared_independently():
    outputs = {
        "getprop": "[ro.build.version.release]: [6.1]\n[ro.product.name]: [rk3568]\n",
        "uname": "OpenHarmony test\n",
        "id": "uid=0(root) gid=0(root)\n",
        "ps": "UID PID PPID CMD\nroot 42 1 service_daemon\n",
        "-A": "UID PID PPID CMD\nroot 42 1 service_daemon\n",
        "/proc/net/unix": "Num RefCount Protocol Flags Type St Inode Path\n",
        "/proc/net/tcp": "sl local rem st\n",
        "/proc/net/tcp6": "",
        "/proc/net/udp": "",
        "/proc/net/udp6": "",
        "/proc/42/attr/current": "u:r:service:s0\n",
        "/proc/42/exe": "/system/bin/service_daemon\n",
        "/system/bin/service_daemon": "a" * 64 + "  /system/bin/service_daemon\n",
    }
    fp = collect_device_fingerprint(
        _FakeHDC(outputs), process_names=["service_daemon"],
        reference={
            "system_properties": {"ro.build.version.release": "6.1", "ro.product.name": "rk3568"},
            "processes": {"service_daemon": {"binary_sha256": "b" * 64}},
        },
    )
    assert fp.status == MISMATCH
    assert fp.version_check["status"] == "mismatch"
    assert any(item["kind"].endswith("binary_sha256") and item["status"] == "mismatch"
               for item in fp.version_check["checks"])

    fp_match = collect_device_fingerprint(
        _FakeHDC(outputs), process_names=["service_daemon"],
        reference={
            "system_properties": {"ro.build.version.release": "6.1", "ro.product.name": "rk3568"},
            "processes": {"service_daemon": {"binary_sha256": "a" * 64}},
        },
    )
    assert fp_match.status == MATCHED
    assert fp_match.version_check["matched_fields"] == 3


def test_missing_reference_fact_is_version_unverified_not_mismatch():
    outputs = {
        "getprop": "[ro.build.version.release]: [6.1]\n",
        "uname": "OpenHarmony test\n",
        "id": "uid=0(root) gid=0(root)\n",
        "ps": "UID PID PPID CMD\n",
        "-A": "UID PID PPID CMD\n",
        "/proc/net/unix": "Num RefCount Protocol Flags Type St Inode Path\n",
        "/proc/net/tcp": "sl local rem st\n",
        "/proc/net/tcp6": "",
        "/proc/net/udp": "",
        "/proc/net/udp6": "",
    }
    fp = collect_device_fingerprint(
        _FakeHDC(outputs),
        reference={"system_properties": {"ro.build.version.incremental": "missing-on-board"}},
    )
    assert fp.status == VERSION_UNVERIFIED
    assert fp.version_check["status"] == "unknown"
    assert fp.version_check["unknown_fields"] == 1
