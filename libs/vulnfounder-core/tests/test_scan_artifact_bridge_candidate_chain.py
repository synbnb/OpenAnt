"""扫描产物桥接时保留 Stage1 候选攻击链。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from core.scan_artifact_bridge import bridge_webui_entry  # noqa: E402


def test_bridge_webui_entry_preserves_candidate_paths(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sp_utils.cpp").write_text("\n" * 20, encoding="utf-8")

    scan = tmp_path / "abcdef12"
    scan.mkdir()
    (scan / "meta.json").write_text(json.dumps({"repo": str(repo)}), encoding="utf-8")
    payload = {
        "results": [{
            "primary_finding_id": "SAMPLE-1",
            "unit_id": "unit-1",
            "finding": "vulnerable",
            "function_analyzed": "SPUtils::LoadCmd",
            "attack_scenario": "UDP 127.0.0.1:8283",
            "reasoning": "unsafe forwarding",
            "findings": [{
                "scope": "target",
                "relation": "primary",
                "file": "sp_utils.cpp",
                "line_start": 1,
                "line_end": 3,
                "reasoning": "popen sink",
            }],
            "stage_context": {
                "stage1": {
                    "candidate_entry_path_ids": [[
                        "sp_thread_socket.cpp:SpThreadSocket::HandleMsg",
                        "Network.cpp:Network::ItemData",
                        "sp_utils.cpp:SPUtils::LoadCmd",
                    ]]
                }
            },
        }],
        "metrics": {},
    }
    (scan / "results.json").write_text(json.dumps(payload), encoding="utf-8")

    bridge, _ = bridge_webui_entry(tmp_path, scan_id="abcdef12", sample="SAMPLE-1")

    assert bridge["候选攻击链"] == [[
        "sp_thread_socket.cpp:SpThreadSocket::HandleMsg",
        "Network.cpp:Network::ItemData",
        "sp_utils.cpp:SPUtils::LoadCmd",
    ]]
    assert "候选攻击链" not in bridge["完整攻击链"]
