"""OpenHarmony profile construction from explicit and repository-local signals."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from core.platforms.base import CoverageReport, RepositoryProfile
from core.platforms.openharmony.gn import OpenHarmonyGNParser
from core.platforms.openharmony.idl import OpenHarmonyIDLParser
from core.platforms.openharmony.manifest import BundleManifestInventory, BundleManifestReader
from core.platforms.openharmony.sa_profile import OpenHarmonySAProfileParser
from core.platforms.openharmony.scope import OpenHarmonyScopeClassifier


_SIGNAL_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
        ".idl",
        ".hcs",
        ".hdc",
        ".gn",
        ".gni",
    }
)
_MAX_SIGNAL_BYTES = 512 * 1024
_MAX_SIGNAL_FILES = 20000
_NAMESPACE_RE = re.compile(r"\bnamespace\s+OHOS\b")
_API_SIGNAL_PATTERNS = {
    "system_ability": re.compile(r"\b(?:SystemAbility|DECLARE_SYSTEM_ABILITY)\b"),
    "binder_ipc": re.compile(r"\b(?:MessageParcel|IRemoteStub|IRemoteProxy)\b"),
    "hdf": re.compile(r"\bHDF_INIT\s*\("),
}


class OpenHarmonyProfileBuilder:
    """Build a profile from explicit signals or bounded local repository metadata.

    ``build`` remains a pure normalizer for caller-supplied evidence.  The
    repository inspection path performs only bounded, read-only manifest/GN
    parsing and never executes repository build code.
    """

    _WEIGHTS = {
        "bundle_manifest": 0.50,
        "gn_target": 0.25,
        "namespace_ohos": 0.25,
    }
    _MIN_CONFIDENCE = 0.75

    def __init__(self, schema_version: int = 1):
        if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version < 1:
            raise ValueError("schema_version must be a positive integer")
        self.schema_version = schema_version

    def build(
        self,
        repository_root: str,
        signals: dict[str, Any] | None = None,
        *,
        components: list[dict[str, Any]] | None = None,
        languages: list[str] | None = None,
        boundaries: list[str] | None = None,
        coverage: CoverageReport | None = None,
        provenance: dict[str, Any] | None = None,
        build_metadata: dict[str, Any] | None = None,
    ) -> RepositoryProfile | None:
        """Return an OpenHarmony profile only when static evidence is sufficient."""
        signals = signals or {}
        evidence = [name for name in self._WEIGHTS if signals.get(name)]
        confidence = sum(self._WEIGHTS[name] for name in evidence)
        if confidence < self._MIN_CONFIDENCE:
            return None

        profile_coverage = coverage or CoverageReport(schema_version=self.schema_version)
        if profile_coverage.schema_version != self.schema_version:
            raise ValueError("coverage schema_version must match the profile schema_version")

        profile_provenance = {"profile_builder_version": self.schema_version}
        if provenance:
            profile_provenance.update(provenance)

        return RepositoryProfile(
            schema_version=self.schema_version,
            platform="openharmony",
            detection={"confidence": confidence, "evidence": evidence},
            repository_root=repository_root,
            components=components or [],
            languages=languages or [],
            boundaries=boundaries or [],
            coverage=profile_coverage,
            provenance=profile_provenance,
            build_metadata=build_metadata or {},
        )

    def inspect_repository(self, repository_root: str | Path) -> dict[str, Any]:
        """Collect bounded, repository-relative platform detection evidence.

        This method never raises for malformed repository metadata.  It returns
        the low-confidence signals even when the caller should keep the generic
        platform mode, so a later coverage layer can explain the fallback.
        """
        root = Path(repository_root).resolve()
        inventory = BundleManifestReader(root).collect()
        classifier = OpenHarmonyScopeClassifier(root)
        build_metadata = classifier.collect_build_metadata()
        build_metadata["gn"] = self._collect_gn_metadata(root)
        build_metadata["idl"] = self._collect_idl_metadata(root)
        build_metadata["sa_profiles"] = self._collect_sa_profile_metadata(root)
        text_signals = self._scan_text_signals(root)

        valid_bundle_paths = [
            manifest.path
            for manifest in inventory.manifests
            if manifest.component_name and manifest.subsystem and manifest.build_targets
        ]
        gn_paths = sorted(
            {
                target["path"]
                for target in build_metadata["gn"].get("targets", [])
                if isinstance(target, dict) and target.get("path")
            }
        )
        signals: dict[str, Any] = {
            "bundle_manifest": valid_bundle_paths,
            "gn_target": gn_paths,
            "namespace_ohos": text_signals["namespace_ohos"],
        }
        evidence = [name for name in self._WEIGHTS if signals.get(name)]
        confidence = sum(self._WEIGHTS[name] for name in evidence)

        return {
            "confidence": confidence,
            "evidence": evidence,
            "signals": {
                **signals,
                "idl": text_signals["idl"],
                "system_ability": text_signals["system_ability"],
                "binder_ipc": text_signals["binder_ipc"],
                "hdf": text_signals["hdf"],
            },
            "manifest_inventory": inventory,
            "build_metadata": build_metadata,
        }

    def build_from_repository(
        self,
        repository_root: str | Path,
        *,
        languages: list[str] | None = None,
        boundaries: list[str] | None = None,
        coverage: CoverageReport | None = None,
    ) -> RepositoryProfile | None:
        """Detect OpenHarmony and build a normalized profile when confidence is sufficient."""
        root = Path(repository_root).resolve()
        inspection = self.inspect_repository(root)
        inventory = inspection["manifest_inventory"]
        assert isinstance(inventory, BundleManifestInventory)

        detected_languages = languages
        if detected_languages is None:
            detected_languages = self._detect_languages(root)

        detected_boundaries = boundaries or self._detect_boundaries(inspection["signals"])
        profile = self.build(
            str(root),
            inspection["signals"],
            components=[manifest.to_component() for manifest in inventory.manifests],
            languages=detected_languages,
            boundaries=detected_boundaries,
            coverage=coverage,
            provenance={
                "manifest_paths": [manifest.path for manifest in inventory.manifests],
                "manifest_parse_failures": list(inventory.parse_failures),
                "build_metadata_paths": sorted(
                    {
                        *(
                            item["path"]
                            for item in inspection["build_metadata"]["build_files"]
                            if item.get("path")
                        ),
                        *inspection["build_metadata"]["gn"].get("files", []),
                    }
                ),
                "idl_paths": list(inspection["build_metadata"]["idl"].get("files", [])),
                "sa_profile_paths": list(
                    inspection["build_metadata"]["sa_profiles"].get("files", [])
                ),
                "source_hashes": {},
            },
            build_metadata=inspection["build_metadata"],
        )
        if profile is None:
            return None

        # Keep path-level signals next to the weighted evidence.  This is
        # useful to coverage/reporting layers and remains plain JSON data.
        profile.detection["signals"] = inspection["signals"]
        profile.detection["manifest_parse_failures"] = list(inventory.parse_failures)
        return profile

    @staticmethod
    def _collect_gn_metadata(root: Path) -> dict[str, Any]:
        """Collect GN details while preserving fail-safe profile detection."""
        try:
            return OpenHarmonyGNParser().collect(root).to_dict()
        except (OSError, UnicodeError, ValueError) as exc:
            return {
                "files": [],
                "targets": [],
                "unknown_conditions": [],
                "unknown_condition_count": 0,
                "parse_failures": [
                    {"path": ".", "reason": f"GN metadata collection failed: {exc}"}
                ],
            }

    @staticmethod
    def _collect_idl_metadata(root: Path) -> dict[str, Any]:
        """Collect IDL contracts while keeping profile detection fail-safe."""
        try:
            return OpenHarmonyIDLParser().collect(root).to_dict()
        except (OSError, UnicodeError, ValueError) as exc:
            return {
                "path": "",
                "files": [],
                "package": "",
                "imports": [],
                "sequenceables": [],
                "interfaces": [],
                "enums": [],
                "structs": [],
                "parse_failures": [
                    {"path": ".", "reason": f"IDL metadata collection failed: {exc}"}
                ],
            }

    @staticmethod
    def _collect_sa_profile_metadata(root: Path) -> dict[str, Any]:
        """Collect SA profiles while keeping profile construction fail-safe."""
        try:
            return OpenHarmonySAProfileParser().collect(root).to_dict()
        except (OSError, UnicodeError, ValueError) as exc:
            return {
                "files": [],
                "profiles": [],
                "parse_failures": [
                    {"path": ".", "reason": f"SA profile collection failed: {exc}"}
                ],
            }

    @staticmethod
    def _detect_languages(root: Path) -> list[str]:
        try:
            from core.parser_adapter import detect_languages

            return list(detect_languages(str(root)))
        except (OSError, ValueError):
            return []

    @staticmethod
    def _detect_boundaries(signals: dict[str, Any]) -> list[str]:
        boundaries: list[str] = []
        if signals.get("binder_ipc"):
            boundaries.append("binder_ipc")
        if signals.get("system_ability"):
            boundaries.append("system_ability")
        if signals.get("hdf"):
            boundaries.append("hdf")
        if signals.get("idl"):
            boundaries.append("idl")
        return boundaries

    @staticmethod
    def _scan_text_signals(root: Path) -> dict[str, list[str]]:
        found = {
            "namespace_ohos": [],
            "idl": [],
            "system_ability": [],
            "binder_ipc": [],
            "hdf": [],
        }
        if not root.is_dir():
            return found

        paths_seen = 0
        for path in sorted(root.rglob("*")):
            if paths_seen >= _MAX_SIGNAL_FILES:
                break
            if path.is_symlink() or not path.is_file() or path.suffix.lower() not in _SIGNAL_SUFFIXES:
                continue
            try:
                path.resolve().relative_to(root)
                if path.stat().st_size > _MAX_SIGNAL_BYTES:
                    continue
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError, ValueError):
                continue

            paths_seen += 1
            relative = path.relative_to(root).as_posix()
            if path.suffix.lower() == ".idl" and len(found["idl"]) < 32:
                found["idl"].append(relative)
            if _NAMESPACE_RE.search(text) and len(found["namespace_ohos"]) < 32:
                found["namespace_ohos"].append(relative)
            for name, pattern in _API_SIGNAL_PATTERNS.items():
                if pattern.search(text) and len(found[name]) < 32:
                    found[name].append(relative)
        return found
