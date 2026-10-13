"""可迁移的 OpenHarmony 工具链路径解析。

工具链不是 Python 源码的必需部分，但运行时优先从 VulnFounder 项目目录
寻找。部署包可以把 command-line-tools 放到 runtime/openharmony 下；用户也
可以通过 VULNFOUNDER_DYNAMIC_TOOLCHAIN 显式指定，或继续使用 assets/toolchains、
PATH。解析器只返回路径，不下载、不修改用户主目录，也不假设某一台开发机的
目录结构。
"""

from __future__ import annotations

from pathlib import Path

from utilities.branding import first_env, project_root


def _looks_like_toolchain(path: Path) -> bool:
    return (
        (path / "hvigor" / "bin" / "hvigorw").is_file()
        or (path / "sdk" / "default" / "openharmony" / "toolchains").is_dir()
    )


def toolchain_root() -> Path:
    """返回显式或项目内可选工具链根；缺失时返回可诊断的候选根。"""

    override = first_env("VULNFOUNDER_DYNAMIC_TOOLCHAIN", "OPENANT_DYNAMIC_TOOLCHAIN")
    if override:
        return Path(override).expanduser().resolve()

    root = project_root()
    bases: list[Path] = []
    if root is not None:
        # runtime is the canonical project-local location.  assets/toolchains
        # remains supported for existing deployments and tests.
        bases.extend([root / "runtime" / "openharmony", root / "assets" / "toolchains"])
    else:
        bases.append(Path("assets/toolchains").resolve())
    for base in bases:
        if _looks_like_toolchain(base):
            return base
        try:
            children = sorted((p for p in base.iterdir() if p.is_dir()), key=lambda p: p.name)
        except OSError:
            children = []
        for child in children:
            if _looks_like_toolchain(child):
                return child
    # Keep the canonical project-local path in diagnostics when nothing is
    # installed; callers can report the missing components without guessing a
    # machine-specific absolute path.
    if root is not None:
        return root / "runtime" / "openharmony"
    return bases[0]


def toolchain_file(relative: str) -> Path:
    return toolchain_root() / relative
