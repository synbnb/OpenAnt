"""通用协议源码证据提取的最小回归测试。"""

from __future__ import annotations

from utilities.openharmony_dynamic.protocol_evidence import infer_protocol_evidence


def test_protocol_evidence_is_scoped_to_route_sources(tmp_path):
    route = tmp_path / "route.cpp"
    unrelated = tmp_path / "unrelated.cpp"
    route.write_text(
        """int Handle(int fd) {
    recvfrom(fd, buf, 128, 0, nullptr, nullptr);
    if (msg.find(\"::\") != std::string::npos) switch (kind) { case 1: return read(fd, buf, 1); }
    sockaddr_in addr{}; addr.sin_port = htons(8283); bind(fd, (sockaddr*)&addr, sizeof(addr));
    VerifyPermission(uid);
}
""",
        encoding="utf-8",
    )
    unrelated.write_text("recvfrom(fd, buf, 1, 0, nullptr, nullptr);", encoding="utf-8")

    result = infer_protocol_evidence(["route.cpp"], repo_root=tmp_path).to_dict()
    assert result["status"] == "complete"
    assert result["counts"]["transport"] >= 2
    assert any(item["signal"] == "8283" for item in result["endpoints"])
    assert any(item["signal"] in {"delimiter", "substring", "literal_separator"} for item in result["framing"])
    assert any(item["signal"] == "switch" for item in result["dispatch"])
    assert any(item["signal"] == "permission" for item in result["guards"])
    assert all(item["path"] == "route.cpp" for category in ("transport", "endpoints", "framing", "dispatch", "guards") for item in result[category])


def test_protocol_evidence_reports_missing_categories(tmp_path):
    source = tmp_path / "plain.cpp"
    source.write_text("int f() { return 1; }\n", encoding="utf-8")
    result = infer_protocol_evidence(["plain.cpp"], repo_root=tmp_path)
    assert result.status == "partial"
    assert "未找到接收/发送/绑定调用证据" in result.missing_evidence
    assert "未找到端点、Unix socket 名称或端口常量" in result.missing_evidence


def test_protocol_evidence_extracts_symbolic_port_constants(tmp_path):
    source = tmp_path / "socket.h"
    source.write_text(
        """class Socket {
    const int udpPort = 8283;
    const int tcpPort = 8284;
    const int udpExPort = 8285;
};
""",
        encoding="utf-8",
    )
    result = infer_protocol_evidence(["socket.h"], repo_root=tmp_path).to_dict()
    assert result["counts"]["endpoints"] == 3
    assert {item["signal"] for item in result["endpoints"]} == {
        "udpPort=8283", "tcpPort=8284", "udpExPort=8285",
    }


def test_protocol_evidence_follows_route_local_include(tmp_path):
    header = tmp_path / "socket.h"
    header.write_text("const int servicePort = 9001;\n", encoding="utf-8")
    source = tmp_path / "server.cpp"
    source.write_text(
        '#include "socket.h"\nint Server(int fd) { return bind(fd, nullptr, 0); }\n',
        encoding="utf-8",
    )
    result = infer_protocol_evidence(["server.cpp"], repo_root=tmp_path).to_dict()
    assert any(item["signal"] == "servicePort=9001" for item in result["endpoints"])
    assert "socket.h" in result["source_paths"]
