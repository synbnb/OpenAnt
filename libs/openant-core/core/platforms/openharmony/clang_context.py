"""Discover or export a bounded Clang compilation context.

OpenHarmony source repositories normally do not carry ``compile_commands.json``.
This module therefore treats compilation-context acquisition as a separate,
auditable step:

1. use an explicitly supplied compilation database;
2. find a bounded existing database near the repository;
3. if a real Ninja build directory exists, export its compile commands with the
   read-only ``ninja -t compdb`` tool;
4. if no build output exists, reconstruct a bounded *candidate* database from
   ``BUILD.gn`` and an available compiler/sysroot;
5. otherwise return ``context_unavailable`` without running a full product
   build or promoting reconstructed flags to strict evidence.

The returned status is provenance, not a security conclusion. A database
exported from a real build directory may be used for that concrete
configuration; a GN-reconstructed database remains candidate-only and does not
prove product equivalence.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}
DEFAULT_RECONSTRUCT_MAX_FILES = 128


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _path(value: str | os.PathLike[str], *, base: Path | None = None) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute() and base is not None:
        candidate = base / candidate
    return candidate.expanduser().resolve()


def _is_source(path: Any) -> bool:
    return Path(_text(path)).suffix.lower() in SOURCE_EXTENSIONS


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _validate_database(path: Path) -> tuple[bool, dict[str, Any]]:
    diagnostics: dict[str, Any] = {
        "path": str(path),
        "entries": 0,
        "source_entries": 0,
        "existing_source_entries": 0,
    }
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        diagnostics["error"] = str(exc)
        return False, diagnostics
    if not isinstance(payload, list):
        diagnostics["error"] = "compile database must be a JSON array"
        return False, diagnostics
    diagnostics["entries"] = len(payload)
    for item in payload:
        if not isinstance(item, Mapping):
            continue
        source = _text(item.get("file"))
        if not _is_source(source):
            continue
        diagnostics["source_entries"] += 1
        directory = _path(item.get("directory") or path.parent, base=path.parent)
        source_path = _path(source, base=directory)
        if source_path.is_file():
            diagnostics["existing_source_entries"] += 1
    ok = diagnostics["source_entries"] > 0 and diagnostics["existing_source_entries"] > 0
    if not ok and "error" not in diagnostics:
        diagnostics["error"] = "no existing C/C++ source entry in compile database"
    return ok, diagnostics


def _normalise_define(value: Any) -> str:
    """Convert a GN define literal to a compiler ``-D`` value."""
    text = _text(value)
    if not text:
        return ""
    text = text.strip().strip('"').strip("'")
    text = text.replace(" ", "")
    return text if text.startswith("-D") else f"-D{text}"


def _source_path(root: Path, value: Any, base: Path) -> Path | None:
    text = _text(value)
    if not text or text.startswith("//"):
        return None
    candidate = _path(text, base=base)
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() and _is_source(candidate) else None


def _repository_roots(root: Path) -> list[Path]:
    """Find bounded sibling roots where OpenHarmony component deps may exist."""
    roots: list[Path] = [root, root.parent, root.parent.parent]
    configured = os.environ.get("OPENANT_SOURCE_ROOTS", "")
    roots.extend(_path(item) for item in configured.split(os.pathsep) if item.strip())
    # The bundled SDK/tooling checkout is useful for local OpenAnt evaluation,
    # but remains only a fallback; production deployments can supply roots via
    # OPENANT_SOURCE_ROOTS instead of depending on this layout.
    try:
        project_root = Path(__file__).resolve().parents[5]
        roots.extend((
            project_root / "source_code_base",
            project_root / "openharmony_reference" / "openharmony_source_code",
        ))
    except (IndexError, OSError):
        pass
    # Reuse dependency bundles produced by a previous OpenAnt evaluation when
    # present. The bundle name and revision remain visible in diagnostics; it
    # is still candidate-only unless a matching product build proves them.
    cache_root = Path.home() / ".openant" / "evaluation"
    if cache_root.is_dir():
        try:
            roots.extend(path for path in cache_root.glob("*/deps") if path.is_dir())
        except OSError:
            pass
    result: list[Path] = []
    seen: set[str] = set()
    for candidate in roots:
        if not candidate.is_dir():
            continue
        key = str(candidate.resolve())
        if key not in seen:
            seen.add(key)
            result.append(candidate.resolve())
    return result


def _dependency_aliases(dep: str) -> list[str]:
    """Return conservative repository aliases for an OpenHarmony external dep."""
    name = _text(dep).split(":", 1)[0]
    aliases = [name]
    known = {
        "hisysevent": ["hiviewdfx_hisysevent", "hiviewdfx_hiview/hisysevent"],
        "hilog": ["hiviewdfx_hilog"],
        "bounds_checking_function": ["third_party_bounds_checking_function"],
        "ipc": ["communication_ipc"],
        "samgr": ["systemabilitymgr_samgr"],
        "init": ["startup_init"],
    }
    aliases.extend(known.get(name, []))
    return list(dict.fromkeys(aliases))


def _dependency_include_dirs(component: Path) -> list[Path]:
    """Collect conventional public include directories from one dependency."""
    candidates = [
        component,
        component / "include",
        component / "interface",
        component / "interfaces",
        component / "interfaces" / "native",
        component / "interfaces" / "innerkits",
        component / "frameworks",
        component / "common",
    ]
    for parent in (component / "interfaces", component / "include", component / "frameworks"):
        if not parent.is_dir():
            continue
        try:
            # Generated/public headers are commonly nested as
            # interfaces/innerkits/include/<subsystem>.  A shallow bounded
            # walk handles that layout without traversing an entire checkout.
            for current, directories, _files in os.walk(parent, followlinks=False):
                current_path = Path(current)
                try:
                    depth = len(current_path.relative_to(parent).parts)
                except ValueError:
                    continue
                if depth > 5:
                    directories[:] = []
                    continue
                directories[:] = sorted(
                    directory for directory in directories
                    if not (current_path / directory).is_symlink()
                )
                candidates.extend(current_path / directory for directory in directories)
        except OSError:
            continue
    result: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate.is_dir():
            continue
        key = str(candidate.resolve())
        if key not in seen:
            seen.add(key)
            result.append(candidate.resolve())
    return result


def _repository_include_dirs(root: Path, *, max_depth: int = 8) -> list[Path]:
    """Collect local ``include`` directories for internal GN dependencies.

    A component's ``deps`` often point at another target in the same checkout,
    while the lexical GN pass cannot evaluate the target graph.  Adding the
    bounded set of public-looking include directories is a conservative way to
    reproduce the hand-built POC include path without pretending that all GN
    variables or generated headers were evaluated.
    """
    result: list[Path] = []
    if not root.is_dir():
        return result
    try:
        for current, directories, _files in os.walk(root, followlinks=False):
            current_path = Path(current)
            try:
                relative = current_path.relative_to(root)
                depth = len(relative.parts)
            except ValueError:
                directories[:] = []
                continue
            if depth >= max_depth:
                directories[:] = []
            else:
                directories[:] = sorted(
                    directory for directory in directories
                    if directory not in {".git", "out", "build", "node_modules"}
                    and not (current_path / directory).is_symlink()
                )
            if current_path.name in {"include", "innerkits"}:
                result.append(current_path.resolve())
    except OSError:
        return result
    unique: list[Path] = []
    seen: set[str] = set()
    for path in result:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _resolve_external_dependencies(
    root: Path, deps: list[str]
) -> tuple[list[Path], list[str], dict[str, list[str]]]:
    include_dirs: list[Path] = []
    unresolved: list[str] = []
    resolved: dict[str, list[str]] = {}
    roots = _repository_roots(root)
    for dep in sorted(set(deps)):
        found: list[Path] = []
        for alias in _dependency_aliases(dep):
            alias_path = Path(alias)
            for source_root in roots:
                candidate = (source_root / alias_path).resolve()
                if candidate.is_dir():
                    found.append(candidate)
                if source_root.is_dir():
                    try:
                        found.extend(
                            child.resolve()
                            for child in source_root.iterdir()
                            if child.is_dir()
                            and (
                                child.name == alias
                                or child.name.startswith(alias + "-")
                                or child.name.endswith("_" + alias)
                            )
                        )
                    except OSError:
                        continue
        if not found:
            unresolved.append(dep)
            continue
        resolved[dep] = list(dict.fromkeys(str(path) for path in found))
        for component in found:
            include_dirs.extend(_dependency_include_dirs(component))
    unique: list[Path] = []
    seen: set[str] = set()
    for path in include_dirs:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique, unresolved, resolved


def _find_candidate_compiler(root: Path) -> tuple[str | None, dict[str, Any]]:
    """Find an OHOS SDK compiler, falling back to host clang for diagnostics."""
    candidates: list[Path] = []
    for variable in ("OPENANT_OHOS_CLANGXX", "OHOS_CLANGXX", "CLANGXX"):
        value = os.environ.get(variable, "").strip()
        if value:
            candidates.append(_path(value))
    try:
        project_root = Path(__file__).resolve().parents[5]
        toolchains = project_root / "libs" / "openant-core" / "utilities" / "dynamic_tester" / "toolchains"
        candidates.extend(sorted(toolchains.glob(
            "*/command-line-tools/sdk/default/openharmony/native/llvm/bin/"
            "*-unknown-linux-ohos-clang++"
        )))
    except (IndexError, OSError):
        pass
    host = shutil.which("clang++")
    if host:
        candidates.append(Path(host))
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        key = str(resolved)
        if key in seen or not resolved.is_file():
            continue
        seen.add(key)
        name = resolved.name
        is_ohos = "-unknown-linux-ohos-clang++" in name
        info: dict[str, Any] = {
            "compiler": str(resolved),
            "kind": "ohos_sdk" if is_ohos else "host",
            "target": "aarch64-unknown-linux-ohos" if is_ohos and name.startswith("aarch64-") else None,
        }
        if is_ohos:
            native_root = resolved.parent.parent.parent
            sysroot = native_root / "sysroot"
            if sysroot.is_dir():
                info["sysroot"] = str(sysroot)
            else:
                info["sysroot_missing"] = str(sysroot)
        return str(resolved), info
    return None, {"compiler": None, "kind": "unavailable"}


def _candidate_compile_databases(root: Path) -> list[Path]:
    candidates: list[Path] = []
    direct = (
        root / "compile_commands.json",
        root / "out" / "compile_commands.json",
        root / "out" / "default" / "compile_commands.json",
        root / "build" / "compile_commands.json",
    )
    candidates.extend(direct)
    for parent in (root / "out", root / "build"):
        if not parent.is_dir():
            continue
        try:
            candidates.extend(sorted(parent.glob("*/compile_commands.json")))
        except OSError:
            continue
    seen: set[str] = set()
    result: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate.absolute()
        key = str(resolved)
        if key in seen or not resolved.is_file():
            continue
        seen.add(key)
        result.append(resolved)
    return result


def _candidate_ninja_dirs(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for candidate in (root, root / "out", root / "build"):
        if (candidate / "build.ninja").is_file():
            candidates.append(candidate)
    for parent in (root / "out", root / "build"):
        if not parent.is_dir():
            continue
        try:
            for build_file in sorted(parent.glob("*/build.ninja")):
                candidates.append(build_file.parent)
        except OSError:
            continue
    seen: set[str] = set()
    result: list[Path] = []
    for candidate in candidates:
        key = str(candidate.resolve())
        if key not in seen:
            seen.add(key)
            result.append(candidate.resolve())
    return result


def _reconstruct_compile_database(
    root: Path,
    output_path: Path,
    *,
    requested_files: list[str] | None,
    priority_files: list[str] | None = None,
    max_files: int,
) -> tuple[bool, dict[str, Any]]:
    """Build candidate commands from bounded GN metadata.

    This is intentionally not a product build. GN expressions, toolchain
    configs and transitive generated headers cannot be reconstructed safely by
    lexical parsing alone. The output is therefore explicitly candidate-only
    and carries unresolved dependencies/conditions for later review.
    """
    diagnostics: dict[str, Any] = {
        "method": "build_gn_candidate_reconstruction",
        "output": str(output_path),
        "status": "candidate_only",
        "requested_files": list(requested_files or []),
    }
    compiler, compiler_info = _find_candidate_compiler(root)
    diagnostics["compiler"] = compiler_info
    if not compiler:
        diagnostics["error"] = "clang_compiler_not_found"
        return False, diagnostics

    try:
        from .gn import OpenHarmonyGNParser

        gn_result = OpenHarmonyGNParser().collect(root)
    except (OSError, ValueError, TypeError) as exc:
        diagnostics["error"] = f"gn_metadata_parse_failed: {exc}"
        return False, diagnostics
    diagnostics["gn_files"] = list(gn_result.files)
    diagnostics["gn_parse_failures"] = list(gn_result.parse_failures)
    diagnostics["unknown_conditions"] = list(gn_result.unknown_conditions)[:128]
    if not gn_result.targets:
        diagnostics["error"] = "no_build_gn_targets"
        return False, diagnostics

    requested: set[Path] = set()
    for value in requested_files or []:
        candidate = _path(value, base=root)
        if candidate.is_file() and _is_source(candidate):
            requested.add(candidate)

    selected: dict[Path, dict[str, Any]] = {}
    shared_by_build_file: dict[str, list[Any]] = {}
    for target in gn_result.targets:
        build_path = root / target.path
        target_dir = build_path.parent
        shared_by_build_file.setdefault(str(build_path), []).append(target)
        for source in target.sources:
            source_path = _source_path(root, source, target_dir)
            if source_path is None:
                continue
            if requested and source_path not in requested:
                continue
            item = selected.setdefault(source_path, {
                "directory": str(target_dir.resolve()),
                "build_file": str(build_path),
                "target": target.name,
                "include_dirs": [],
                "defines": [],
                "external_deps": [],
                "cflags_cc": [],
                "unknown_conditions": [],
            })
            item["include_dirs"].extend(target.include_dirs)
            item["defines"].extend(target.defines)
            item["external_deps"].extend(target.external_deps)
            item["cflags_cc"].extend(target.cflags_cc)
            item["unknown_conditions"].extend(target.unknown_conditions)

    # A component can omit a source from the simple GN subset (for example,
    # via a variable expansion). Preserve requested files as fallback entries
    # so the caller receives a concrete diagnostic rather than silent loss.
    for source_path in sorted(requested):
        selected.setdefault(source_path, {
            "directory": str(source_path.parent),
            "build_file": None,
            "target": None,
            "include_dirs": [],
            "defines": [],
            "external_deps": [],
            "cflags_cc": [],
            "unknown_conditions": ["source_not_listed_by_lexical_gn_parser"],
        })
    if not selected:
        diagnostics["error"] = "no_requested_sources_in_build_gn"
        return False, diagnostics

    priority_order = {
        str(_path(value, base=root)): index
        for index, value in enumerate(priority_files or [])
        if _text(value)
    }
    selected_items = list(
        sorted(
            selected.items(),
            key=lambda item: (
                0 if str(item[0]) in priority_order else 1,
                priority_order.get(str(item[0]), 10**9),
                str(item[0]),
            ),
        )
    )[: max(1, int(max_files))]
    all_external: list[str] = []
    for _path_value, item in selected_items:
        all_external.extend(item["external_deps"])
    dependency_includes, unresolved_deps, resolved_deps = _resolve_external_dependencies(
        root, all_external
    )
    diagnostics["unresolved_external_deps"] = unresolved_deps
    diagnostics["resolved_external_deps"] = resolved_deps
    diagnostics["dependency_search_roots"] = [str(path) for path in _repository_roots(root)]
    diagnostics["selected_files"] = [str(path) for path, _item in selected_items]
    diagnostics["selected_file_count"] = len(selected_items)
    diagnostics["truncated"] = len(selected) > len(selected_items)
    repository_include_dirs = _repository_include_dirs(root)
    diagnostics["repository_include_dirs"] = [str(path) for path in repository_include_dirs]

    entries: list[dict[str, Any]] = []
    for source_path, item in selected_items:
        build_path = Path(item["build_file"]) if item["build_file"] else source_path.parent / "BUILD.gn"
        target_dir = build_path.parent
        include_dirs: list[Path] = [source_path.parent, target_dir]
        for include_value in item["include_dirs"]:
            include = _path(include_value, base=target_dir)
            if include.is_dir():
                include_dirs.append(include)
        # The shared-header target and executable target may live in the same
        # BUILD.gn. Include their conventional public directories as well.
        for shared_target in shared_by_build_file.get(str(build_path), []):
            for include_value in shared_target.include_dirs:
                include = _path(include_value, base=target_dir)
                if include.is_dir():
                    include_dirs.append(include)
            item["cflags_cc"].extend(shared_target.cflags_cc)
        for parent in (root, root / "include", root / "interface", root / "interfaces"):
            if parent.is_dir():
                include_dirs.append(parent)
        include_dirs.extend(repository_include_dirs)
        include_dirs.extend(dependency_includes)
        unique_includes: list[str] = []
        seen_includes: set[str] = set()
        for include in include_dirs:
            key = str(include.resolve())
            if key not in seen_includes:
                seen_includes.add(key)
                unique_includes.append(key)

        arguments: list[str] = [compiler, "-std=c++17", "-fsyntax-only", "-fno-color-diagnostics"]
        target = compiler_info.get("target")
        if target:
            arguments.append(f"--target={target}")
        if compiler_info.get("sysroot"):
            arguments.append(f"--sysroot={compiler_info['sysroot']}")
        arguments.extend(f"-I{include}" for include in unique_includes)
        arguments.extend(
            define for define in (_normalise_define(value) for value in item["defines"])
            if define
        )
        for flag in item["cflags_cc"]:
            flag_text = _text(flag)
            if flag_text.startswith("-D"):
                normalized = _normalise_define(flag_text)
                if normalized:
                    arguments.append(normalized)
            elif flag_text.startswith(("-std=", "-f", "-W")):
                arguments.append(flag_text)
            elif flag_text.startswith("-I"):
                include_value = flag_text[2:].strip()
                include = _path(include_value, base=target_dir)
                if include.is_dir():
                    arguments.append(f"-I{include}")
        arguments.append(str(source_path))
        entries.append({
            "directory": item["directory"],
            "file": str(source_path),
            "arguments": arguments,
        })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8")
    valid, validation = _validate_database(output_path)
    diagnostics["database_validation"] = validation
    diagnostics["entries"] = len(entries)
    if not valid:
        diagnostics["error"] = "reconstructed_database_invalid"
        try:
            output_path.unlink()
        except OSError:
            pass
        return False, diagnostics
    diagnostics["sha256"] = _hash_file(output_path)
    return True, diagnostics


def _export_ninja_compdb(
    build_dir: Path,
    output_path: Path,
    *,
    timeout_seconds: int,
    ninja: str | None = None,
) -> tuple[bool, dict[str, Any]]:
    executable = ninja or shutil.which("ninja")
    diagnostics: dict[str, Any] = {
        "build_dir": str(build_dir),
        "ninja": executable or "",
        "output": str(output_path),
        "method": "ninja_-t_compdb",
    }
    if not executable:
        diagnostics["error"] = "ninja_not_found"
        return False, diagnostics
    # OpenHarmony build files often use custom rule names.  An unfiltered
    # compdb query is therefore the primary attempt; the conventional rule
    # names remain a compatibility fallback for older Ninja versions.
    command_variants = [
        [executable, "-C", str(build_dir), "-t", "compdb"],
        [executable, "-C", str(build_dir), "-t", "compdb", "cc", "cxx", "objc", "objcxx"],
    ]
    attempts: list[dict[str, Any]] = []
    for command in command_variants:
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=max(1, int(timeout_seconds)),
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            attempts.append({"command": command, "error": str(exc)})
            continue
        attempt: dict[str, Any] = {"command": command, "returncode": completed.returncode}
        if completed.returncode != 0:
            attempt["stderr"] = (completed.stderr or "")[-4000:]
            attempts.append(attempt)
            continue
        try:
            payload = json.loads(completed.stdout or "[]")
        except ValueError as exc:
            attempt["error"] = f"ninja compdb output is not JSON: {exc}"
            attempts.append(attempt)
            continue
        if not isinstance(payload, list) or not any(
            isinstance(item, Mapping) and _is_source(item.get("file")) for item in payload
        ):
            attempt["error"] = "ninja compdb returned no C/C++ entries"
            attempts.append(attempt)
            continue
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        valid, database_diagnostics = _validate_database(output_path)
        attempt["entries"] = len(payload)
        attempt["database_validation"] = database_diagnostics
        if not valid:
            attempt["error"] = "ninja compdb contains no existing source entry"
            try:
                output_path.unlink()
            except OSError:
                pass
            attempts.append(attempt)
            continue
        diagnostics["attempts"] = attempts + [attempt]
        diagnostics["entries"] = len(payload)
        diagnostics["sha256"] = _hash_file(output_path)
        return True, diagnostics
    diagnostics["attempts"] = attempts
    diagnostics["error"] = "ninja_compdb_unusable"
    return False, diagnostics


def _repository_revision(root: Path) -> str:
    """Return a best-effort checkout identity without requiring Git."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    revision = (completed.stdout or "").strip()
    return revision if completed.returncode == 0 and revision else "unknown"


def prepare_clang_context(
    repository: str | os.PathLike[str],
    *,
    explicit_compile_commands: str | os.PathLike[str] | None = None,
    output_dir: str | os.PathLike[str] | None = None,
    timeout_seconds: int = 30,
    ninja: str | None = None,
    requested_files: list[str] | None = None,
    priority_files: list[str] | None = None,
    auto_reconstruct: bool = True,
    max_files: int = DEFAULT_RECONSTRUCT_MAX_FILES,
) -> dict[str, Any]:
    """Discover or reconstruct a bounded compilation database.

    ``auto_reconstruct`` only creates candidate commands from lexical GN
    metadata. It never invokes GN/Ninja build targets and never claims that
    generated headers or product defines are complete.
    """
    root = _path(repository)
    if output_dir:
        destination = _path(output_dir, base=root)
    else:
        # Never create generated files inside a source checkout merely because
        # a caller used the library API directly. The scanner passes its own
        # artifact directory explicitly; this fallback is a bounded temp/cache
        # location for standalone discovery.
        key = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
        destination = Path(tempfile.gettempdir()) / "openant-clang-context" / key
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "repository": str(root),
        "repository_revision": _repository_revision(root),
        "status": "context_unavailable",
        "compile_commands": None,
        "source": None,
        "diagnostics": [],
        "tools": {
            "ninja": ninja or shutil.which("ninja") or "",
            "gn": shutil.which("gn") or "",
            "hb": shutil.which("hb") or "",
        },
    }

    candidates: list[tuple[Path, str]] = []
    if explicit_compile_commands:
        candidates.append((_path(explicit_compile_commands, base=root), "explicit"))
    candidates.extend((path, "repository") for path in _candidate_compile_databases(root))
    for candidate, source in candidates:
        if not candidate.is_file():
            report["diagnostics"].append({"source": source, "path": str(candidate), "error": "not_found"})
            continue
        valid, diagnostics = _validate_database(candidate)
        diagnostics["source"] = source
        if valid:
            report.update({
                "status": "compile_database_found",
                "compile_commands": str(candidate),
                "source": source,
            })
            report["diagnostics"].append(diagnostics)
            return report
        report["diagnostics"].append(diagnostics)

    ninja_dirs = _candidate_ninja_dirs(root)
    report["ninja_candidates"] = [str(path) for path in ninja_dirs]
    for index, build_dir in enumerate(ninja_dirs):
        output_path = destination / f"compile_commands.ninja_export.{index}.json"
        ok, diagnostics = _export_ninja_compdb(
            build_dir,
            output_path,
            timeout_seconds=timeout_seconds,
            ninja=ninja,
        )
        report["diagnostics"].append(diagnostics)
        if ok:
            report.update({
                "status": "ninja_compdb_exported",
                "compile_commands": str(output_path),
                "source": "ninja",
            })
            return report

    if auto_reconstruct:
        reconstruction_path = destination / "compile_commands.gn_candidate.json"
        ok, diagnostics = _reconstruct_compile_database(
            root,
            reconstruction_path,
            requested_files=requested_files,
            priority_files=priority_files,
            max_files=max_files,
        )
        report["diagnostics"].append(diagnostics)
        if ok:
            report.update({
                "status": "reconstructed_candidate",
                "compile_commands": str(reconstruction_path),
                "source": "build_gn_reconstruction",
                "build_admission": "candidate_only",
            })
            return report

    report["diagnostics"].append({
        "error": "no_compile_database_or_ninja_build_output",
        "next_step": "provide a matching OpenHarmony out directory or explicit compile_commands.json",
    })
    return report


__all__ = ["SCHEMA_VERSION", "prepare_clang_context"]
