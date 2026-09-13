"""对项目内 source_code_base 的真实 OpenHarmony socket 清单回归。

该测试不把“本地部分仓库未命中”误判成全量源码不存在；它只校验清单
完整、强字面命中稳定，以及已知的服务别名确实被保留下来。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.source_locator import LocalCorpusClient


CORE_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = CORE_ROOT.parents[1]
SOURCE_ROOT = PROJECT_ROOT / "source_code_base"
TARGETS_FILE = Path(__file__).parent / "fixtures" / "socket_targets.txt"


@pytest.mark.skipif(not SOURCE_ROOT.is_dir(), reason="项目未提供 source_code_base，跳过真实 corpus 回归")
def test_all_socket_targets_are_scanned_against_real_project_corpus() -> None:
    targets = [
        line.strip()[2:]
        for line in TARGETS_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("- ")
    ]
    matches = LocalCorpusClient(
        SOURCE_ROOT,
        max_file_bytes=2 * 1024 * 1024,
        max_total_files=200_000,
    ).scan_targets(targets, max_samples_per_target=8)

    assert len(targets) == 22
    assert set(matches) == set(targets)
    # These three are directly visible in the cloned communication repository
    # or app-manager client code and form stable strong-hit regressions.
    assert matches["/dev/unix/socket/dnsproxyd"].full_path_hits >= 1
    assert matches["/dev/unix/socket/fwmarkd"].full_path_hits >= 1
    assert matches["/dev/unix/socket/NWebSpawn"].full_path_hits >= 1
    # AppSpawn variants are passed as lowercase service aliases in the client
    # manager; requiring alias hits prevents a future case-sensitive-only
    # regression from silently dropping these targets.
    for target in ("CJAppSpawn", "NativeSpawn", "HybridSpawn"):
        assert matches[f"/dev/unix/socket/{target}"].casefold_basename_hits > 0
