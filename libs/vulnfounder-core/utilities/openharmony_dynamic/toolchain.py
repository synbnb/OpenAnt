"""可迁移的 OpenHarmony 工具链路径解析。

工具链不是 Python 源码的必需部分，但运行时优先从 VulnFounder 项目目录
寻找。部署包可以把 command-line-tools 放到 runtime/openharmony 下；用户也
可以通过 VULNFOUNDER_DYNAMIC_TOOLCHAIN 显式指定，或继续使用 assets/toolchains、
PATH。解析器只返回路径，不下载、不修改用户主目录，也不假设某一台开发机的
目录结构。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

from utilities.branding import first_env, project_root


DEFAULT_OPENHARMONY_VERSION = "7.0"
DEFAULT_OPENHARMONY_REVISION = "OpenHarmony-7.0-Release"


def target_openharmony_version(environ: Mapping[str, str] | None = None) -> str:
    """Return the OpenHarmony major/minor version selected for dynamic tools.

    The project default moved to 7.0.  An explicit environment override is
    retained for controlled legacy replays, but an installed 6.1 toolchain is
    no longer selected implicitly when the target is 7.0.
    """

    values = os.environ if environ is None else environ
    raw = (values.get("VULNFOUNDER_OPENHARMONY_VERSION") or
           values.get("OPENANT_OPENHARMONY_VERSION") or "").strip()
    if not raw:
        return DEFAULT_OPENHARMONY_VERSION
    if raw.lower().startswith("openharmony-"):
        raw = raw[len("OpenHarmony-"):]
    if raw.lower().endswith("-release"):
        raw = raw[:-len("-Release")]
    return raw.strip() or DEFAULT_OPENHARMONY_VERSION


def target_openharmony_revision(environ: Mapping[str, str] | None = None) -> str:
    version = target_openharmony_version(environ)
    values = os.environ if environ is None else environ
    explicit = (values.get("VULNFOUNDER_OPENHARMONY_REVISION") or
                values.get("OPENANT_OPENHARMONY_REVISION") or "").strip()
    if explicit:
        return explicit
    return f"OpenHarmony-{version}-Release"


def _looks_like_toolchain(path: Path) -> bool:
    return (
        (path / "hvigor" / "bin" / "hvigorw").is_file()
        or (path / "sdk" / "default" / "openharmony" / "toolchains").is_dir()
    )


def _manifest_version(path: Path) -> str:
    manifest = path / "manifest.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return ""
    value = data.get("openharmony_version") if isinstance(data, dict) else ""
    return str(value).strip()


def _version_matches(path: Path, target_version: str) -> bool:
    manifest_version = _manifest_version(path)
    if manifest_version:
        return manifest_version == target_version
    # A versioned directory without a manifest is accepted only when it is
    # explicitly named for the requested version.  This keeps old bundles
    # usable while preventing a silent 6.1 -> 7.0 fallback.
    return target_version in path.name


def toolchain_root() -> Path:
    """返回显式或项目内可选工具链根；缺失时返回可诊断的候选根。"""

    override = first_env("VULNFOUNDER_DYNAMIC_TOOLCHAIN", "OPENANT_DYNAMIC_TOOLCHAIN")
    if override:
        return Path(override).expanduser().resolve()

    target_version = target_openharmony_version()

    root = project_root()
    bases: list[Path] = []
    if root is not None:
        # runtime is the canonical project-local location.  assets/toolchains
        # remains supported for existing deployments and tests.
        bases.extend([root / "runtime" / "openharmony", root / "assets" / "toolchains"])
    else:
        bases.append(Path("assets/toolchains").resolve())
    for base in bases:
        if _looks_like_toolchain(base) and _version_matches(base, target_version):
            return base
        try:
            children = sorted((p for p in base.iterdir() if p.is_dir()), key=lambda p: p.name)
        except OSError:
            children = []
        for child in children:
            if _looks_like_toolchain(child) and _version_matches(child, target_version):
                return child
    # Keep the canonical project-local path in diagnostics when nothing is
    # installed; callers can report the missing components without guessing a
    # machine-specific absolute path.
    if root is not None:
        return root / "runtime" / "openharmony"
    return bases[0]


def toolchain_file(relative: str) -> Path:
    return toolchain_root() / relative
