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


def _sdk_api_versions(path: Path) -> set[str]:
    """读取 SDK 元数据中的 API 版本，用于配对独立安装的构建工具。"""

    versions: set[str] = set()
    sdk_pkg = path / "sdk" / "default" / "sdk-pkg.json"
    try:
        metadata = json.loads(sdk_pkg.read_text(encoding="utf-8"))
        value = str(metadata.get("data", {}).get("apiVersion", "")).strip()
        if value:
            versions.add(value)
    except (OSError, ValueError, TypeError, AttributeError):
        pass

    # OpenHarmony 的 L2 SDK 有时只打包组件清单，不带 sdk-pkg.json；只查
    # 固定组件位置，不递归遍历整个数 GB 的 SDK 目录。
    sdk = path / "sdk" / "default" / "openharmony"
    for component in ("ets", "js", "native", "toolchains", "previewer"):
        manifest = sdk / component / "oh-uni-package.json"
        try:
            metadata = json.loads(manifest.read_text(encoding="utf-8"))
            value = str(metadata.get("apiVersion", "")).strip()
            if value:
                versions.add(value)
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    return versions


def _build_tools_available(path: Path) -> bool:
    """Hvigor、Node 是 HAP 构建的必需工具；仅有 SDK/hdc 不算完整构建器。"""

    hvigor = path / "hvigor" / "bin" / "hvigorw"
    node_root = path / "tool" / "node"
    node = node_root / "bin" / "node"
    return hvigor.is_file() and node.is_file()


def _build_tool_candidates(bases: list[Path]) -> list[Path]:
    """列出合并工具链和独立 Command Line Tools 的标准安装根。"""

    candidates: list[Path] = []
    for base in bases:
        candidates.append(base)
        try:
            children = sorted((p for p in base.iterdir() if p.is_dir()), key=lambda p: p.name)
        except OSError:
            children = []
        for child in children:
            candidates.extend((child, child / "command-line-tools"))
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate.resolve())
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def build_tools_root() -> Path:
    """解析 Hvigor/Node 根目录，可与目标 OpenHarmony SDK 分开安装。

    例如 7.0 L2 SDK 只包含 SDK、hdc 和签名工具，而 Command Line Tools
    独立包含 Hvigor/Node。只有两边 API 版本相符时才自动配对，避免误用
    6.1 或其他 API 版本的构建工具。显式环境变量适用于受控部署。
    """

    override = first_env("VULNFOUNDER_DYNAMIC_BUILD_TOOLS", "OPENANT_DYNAMIC_BUILD_TOOLS")
    if override:
        return Path(override).expanduser().resolve()

    sdk_root = toolchain_root()
    if _build_tools_available(sdk_root):
        return sdk_root

    project = project_root()
    bases: list[Path] = []
    if project is not None:
        bases.extend([
            project / "runtime" / "openharmony",
            project / "assets" / "toolchains",
        ])
    target_apis = _sdk_api_versions(sdk_root)
    target_version = target_openharmony_version()
    for candidate in _build_tool_candidates(bases):
        if not _build_tools_available(candidate):
            continue
        candidate_apis = _sdk_api_versions(candidate)
        if target_apis and candidate_apis and target_apis.intersection(candidate_apis):
            return candidate
        # 同一完整工具链带版本 manifest 时，即使 SDK 未导出 API 元数据也可
        # 依据明确版本配对；无 manifest 的独立包不能靠名字猜测兼容性。
        if _version_matches(candidate, target_version):
            return candidate

    # 保持失败诊断包含预期的项目内目录；调用方应再用
    # hap_build_toolchain_issues() 明确指出缺失组件。
    return sdk_root


def hap_build_toolchain_issues(root: Path | None = None) -> list[str]:
    """返回 HAP 编译器前置缺项；不运行命令，也不修改本机状态。"""

    selected = root or build_tools_root()
    issues: list[str] = []
    required = {
        "Hvigor 启动器": selected / "hvigor" / "bin" / "hvigorw",
        "Node.js": selected / "tool" / "node" / "bin" / "node",
    }
    for label, path in required.items():
        if not path.is_file():
            issues.append(f"{label}不存在：{path}")
    return issues


def toolchain_file(relative: str) -> Path:
    return toolchain_root() / relative
