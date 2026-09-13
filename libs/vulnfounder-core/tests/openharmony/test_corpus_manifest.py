"""Contract tests for the external OpenHarmony reference corpus.

The full OpenHarmony repositories are intentionally not copied into VulnFounder.
Their location is supplied through ``OPENHARMONY_CORPUS_ROOT`` when running the
local integration check, while the committed manifest keeps the expected
snapshot portable and reviewable.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest


TESTS_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = TESTS_ROOT / "fixtures" / "openharmony" / "corpus_manifest.json"

EXPECTED_REPOSITORIES = {
    "arkweb_arkweb_cangjie_wrapper",
    "communication_netmanager_base",
    "communication_wifi",
    "drivers_peripheral",
    "sensors_medical_sensor",
}

SOURCE_COUNT_KEYS = {
    "cpp",
    "h",
    "c",
    "rs",
    "ets",
    "ts",
    "js",
    "cj",
    "idl",
    "build_gn",
    "gni",
    "bundle_json",
}

SUFFIX_TO_COUNT_KEY = {
    ".cpp": "cpp",
    ".h": "h",
    ".c": "c",
    ".rs": "rs",
    ".ets": "ets",
    ".ts": "ts",
    ".js": "js",
    ".cj": "cj",
    ".idl": "idl",
    ".gni": "gni",
}


@pytest.fixture(scope="module")
def corpus_manifest() -> dict:
    assert MANIFEST_PATH.is_file(), (
        "OpenHarmony corpus manifest is missing: "
        f"{MANIFEST_PATH.relative_to(TESTS_ROOT.parent)}"
    )
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _tracked_files(repo: Path) -> list[Path]:
    output = _git(repo, "ls-files", "-z")
    return [Path(item) for item in output.split("\0") if item]


def _source_counts(files: list[Path]) -> dict[str, int]:
    counts = dict.fromkeys(SOURCE_COUNT_KEYS, 0)
    for path in files:
        if path.name == "BUILD.gn":
            counts["build_gn"] += 1
        elif path.name == "bundle.json":
            counts["bundle_json"] += 1
        elif key := SUFFIX_TO_COUNT_KEY.get(path.suffix.lower()):
            counts[key] += 1
    return counts


def test_manifest_is_portable_complete_and_versioned(corpus_manifest):
    assert corpus_manifest["schema_version"] == 1

    repositories = corpus_manifest["repositories"]
    assert {repo["name"] for repo in repositories} == EXPECTED_REPOSITORIES
    assert len(repositories) == len(EXPECTED_REPOSITORIES)

    for repo in repositories:
        assert Path(repo["name"]).name == repo["name"]
        assert re.fullmatch(r"[0-9a-f]{40}", repo["commit"])
        assert repo["phase"]
        assert set(repo["source_counts"]) == SOURCE_COUNT_KEYS
        assert all(
            isinstance(count, int) and count >= 0
            for count in repo["source_counts"].values()
        )
        assert repo["expected_signals"]
        for pattern in repo["expected_signals"]:
            assert pattern
            assert not Path(pattern).is_absolute()
            assert ".." not in Path(pattern).parts

    serialized = json.dumps(corpus_manifest)
    assert "/Users/" not in serialized
    assert "OPENHARMONY_CORPUS_ROOT" in corpus_manifest["external_root_env"]


def test_external_corpus_matches_pinned_snapshot(corpus_manifest):
    configured_root = os.environ.get(corpus_manifest["external_root_env"])
    if not configured_root:
        pytest.skip(
            f"set {corpus_manifest['external_root_env']} to validate the full "
            "external OpenHarmony corpus"
        )

    corpus_root = Path(configured_root).resolve()
    assert corpus_root.is_dir()

    for expected in corpus_manifest["repositories"]:
        repo = corpus_root / expected["name"]
        assert repo.is_dir(), f"missing reference repository: {repo}"
        assert _git(repo, "rev-parse", "HEAD") == expected["commit"]
        assert _source_counts(_tracked_files(repo)) == expected["source_counts"]

        for pattern in expected["expected_signals"]:
            assert next(repo.glob(pattern), None) is not None, (
                f"{expected['name']} is missing expected signal matching {pattern!r}"
            )
