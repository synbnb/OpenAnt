"""本地 corpus 适配器的安全边界和检索回归。"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.source_locator import LocalCorpusClient, LocalCorpusError


def test_local_corpus_maps_repositories_and_reads_bounded_source(tmp_path: Path) -> None:
    repo = tmp_path / "communication_ipc"
    repo.mkdir()
    source = repo / "service.cpp"
    source.write_text(
        '#define SOCKET_NAME "/dev/unix/socket/demo"\n'
        "int connect(int fd) { return fd; }\n",
        encoding="utf-8",
    )
    (repo / "service.cfg").write_text("socket=/dev/unix/socket/demo\n", encoding="utf-8")

    client = LocalCorpusClient(tmp_path)
    response = client.search(full="/dev/unix/socket/demo", file_type="c", max_results=10, max_hits_per_file=5)
    assert "/openharmony/communication_ipc/service.cpp" in response.results
    document = client.read_source("/openharmony/communication_ipc/service.cpp", max_bytes=24)
    assert document.truncated is True
    assert document.source == "local_corpus"

    path_response = client.search(path="service.cpp", file_type="c", max_results=10, max_hits_per_file=2)
    assert set(path_response.results) == {"/openharmony/communication_ipc/service.cpp"}


def test_local_corpus_rejects_escape_and_symlink(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.c").write_text("int a;\n", encoding="utf-8")
    outside = tmp_path / "outside.c"
    outside.write_text("secret", encoding="utf-8")
    (repo / "outside.c").symlink_to(outside)
    client = LocalCorpusClient(tmp_path)

    with pytest.raises(LocalCorpusError):
        client.read_source("/openharmony/../outside.c")
    with pytest.raises(LocalCorpusError):
        client.read_source("/openharmony/repo/outside.c")


def test_local_corpus_probe_is_explicitly_local() -> None:
    # The fixture itself is sufficient for this contract; no network request
    # is made and the warning prevents callers from presenting it as OpenGrok.
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        result = LocalCorpusClient(directory).probe()
    assert result.reachable is True
    assert result.base_url == "local://source_code_base"
    assert any("离线本地回归" in warning for warning in result.warnings)


def test_local_corpus_scans_multiple_targets_in_one_pass(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "socket.c").write_text(
        'const char *a = "/dev/unix/socket/demo";\n'
        'const char *b = "DEMO";\n',
        encoding="utf-8",
    )
    client = LocalCorpusClient(tmp_path)
    matches = client.scan_targets(("/dev/unix/socket/demo", "/dev/unix/socket/Demo"))
    assert matches["/dev/unix/socket/demo"].full_path_hits == 1
    assert matches["/dev/unix/socket/demo"].basename_hits == 1
    assert matches["/dev/unix/socket/Demo"].casefold_basename_hits == 2


def test_socket_target_fixture_covers_every_requested_service() -> None:
    fixture = Path(__file__).parent / "fixtures" / "socket_targets.txt"
    targets = [line.strip()[2:] for line in fixture.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(targets) == 22
    with pytest.raises(LocalCorpusError):
        LocalCorpusClient(Path(__file__).parent).scan_targets(targets[:1] + ["/tmp/../unsafe"])
