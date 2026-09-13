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


def data_dir() -> Path:
    """Resolve the operator-owned data root with a non-destructive fallback.

    A fresh installation uses ``~/.vulnfounder``.  Existing ``~/.openant``
    data remains readable until the user explicitly migrates it.
    """
    override = first_env("VULNFOUNDER_DATA_DIR", "OPENANT_DATA_DIR")
    if override:
        return Path(override).expanduser()
    home = Path.home()
    primary = home / ".vulnfounder"
    legacy = home / ".openant"
    if primary.is_dir() or not legacy.is_dir():
        return primary
    return legacy


def schema_version(name: str, version: str) -> str:
    """Build a canonical VulnFounder schema identifier."""
    return f"{PRODUCT_SLUG}.{name}.{version}"


def legacy_schema_version(name: str, version: str) -> str:
    """Build the legacy identifier accepted by migration readers."""
    return f"{LEGACY_PRODUCT_SLUG}.{name}.{version}"


def schema_matches(value: object, name: str, version: str) -> bool:
    """Accept both the canonical and legacy schema identifier."""
    return value in {schema_version(name, version), legacy_schema_version(name, version)}
