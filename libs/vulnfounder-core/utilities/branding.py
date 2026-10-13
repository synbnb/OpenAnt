"""Shared product-brand and migration helpers.

VulnFounder is the canonical product identity.  The legacy ``openant`` names
remain accepted on input for existing workspaces and automation. New files,
environment variables and user-facing messages use the VulnFounder spelling.
Versioned wire schemas are migrated conservatively: readers accept both
spellings, while a schema is only renamed when its producer and all consumers
can be upgraded together.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

PRODUCT_NAME = "VulnFounder"
PRODUCT_SLUG = "vulnfounder"
LEGACY_PRODUCT_SLUG = "openant"


def first_env(primary: str, legacy: str | None = None,
              environ: Mapping[str, str] | None = None) -> str:
    """Return a non-empty primary environment value, then its legacy alias."""
    env = os.environ if environ is None else environ
    value = str(env.get(primary, "")).strip()
    if value:
        return value
    if legacy:
        return str(env.get(legacy, "")).strip()
    return ""


def setdefault_env(primary: str, legacy: str | None, default: str) -> str:
    """Set the canonical variable only when neither spelling is configured.

    An operator's legacy value still wins, while newly spawned workers see the
    canonical VulnFounder spelling.
    """
    value = first_env(primary, legacy)
    if value:
        return value
    os.environ[primary] = default
    return default


def _is_project_root(path: Path) -> bool:
    return (
        path.is_dir()
        and (path / "config" / "models.json").is_file()
        and (
            (path / "libs" / "vulnfounder-core" / "pyproject.toml").is_file()
            or (path / "libs" / "openant-core" / "pyproject.toml").is_file()
        )
    )


def project_root() -> Path | None:
    """Find the checkout that owns VulnFounder runtime files.

    Explicit VULNFOUNDER_PROJECT_ROOT wins.  For an editable checkout, package
    parents are deterministic.  The current working directory is deliberately
    not trusted because it may be an untrusted repository being scanned.
    """
    explicit = first_env("VULNFOUNDER_PROJECT_ROOT", "OPENANT_PROJECT_ROOT")
    if explicit:
        root = Path(explicit).expanduser().resolve()
        if not _is_project_root(root):
            raise ValueError(f"{root} 不是有效的 VulnFounder 项目根目录")
        return root

    candidates: list[Path] = []
    try:
        candidates.extend(Path(__file__).resolve().parents)
    except OSError:
        pass
    seen: set[Path] = set()
    for candidate in candidates:
        candidate = candidate.resolve()
        if candidate in seen:
            continue
        seen.add(candidate)
        if _is_project_root(candidate):
            return candidate
    return None


def data_dir() -> Path:
    """Resolve the relocatable runtime data root.

    A VulnFounder checkout stores generated artifacts in ``<root>/result``.
    VULNFOUNDER_DATA_DIR is an explicit deployment override.  Unlike the
    historical OpenAnt implementation, new runs never default to a hidden
    machine-specific hidden directory.
    """
    override = first_env("VULNFOUNDER_DATA_DIR", "OPENANT_DATA_DIR")
    if override:
        return Path(override).expanduser()
    root = project_root()
    if root is not None:
        return root / "result"
    raise RuntimeError(
        "无法确定 VulnFounder 项目运行数据目录；请从项目目录运行，或设置 "
        "VULNFOUNDER_PROJECT_ROOT / VULNFOUNDER_DATA_DIR"
    )


def schema_version(name: str, version: str) -> str:
    """Build a canonical VulnFounder schema identifier."""
    return f"{PRODUCT_SLUG}.{name}.{version}"


def legacy_schema_version(name: str, version: str) -> str:
    """Build the legacy identifier accepted by migration readers."""
    return f"{LEGACY_PRODUCT_SLUG}.{name}.{version}"


def schema_matches(value: object, name: str, version: str) -> bool:
    """Accept both the canonical and legacy schema identifier."""
    return value in {schema_version(name, version), legacy_schema_version(name, version)}
