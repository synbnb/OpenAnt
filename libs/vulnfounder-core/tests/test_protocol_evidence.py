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
