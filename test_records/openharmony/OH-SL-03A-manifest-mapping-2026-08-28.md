# OH-SL-03A：OpenHarmony Manifest 仓库映射测试记录

日期：2026-08-28
阶段：源码定位器 SL-03A（Manifest XML 解析、最长前缀匹配和仓库映射）
性质：本地离线测试，不调用大模型、不访问远端 Manifest、不执行 Git clone

## 1. 原项目逻辑与修改后逻辑

原项目可以得到 OpenGrok 的源码路径，例如：

```text
/openharmony/base/startup/init/services/param/linux/param_service.c
```

但路径本身不能可靠推出 GitCode 仓库。直接把 `base/startup/init` 拼成仓库名会把模型猜测当成事实，也无法处理多个项目路径前缀、Manifest 默认 remote/revision 或版本不一致。

本阶段新增 `core/source_locator/manifest_resolver.py`，流程变为：

```text
本地 Manifest XML
  → 大小限制和 XML 安全检查
  → 解析 remote/default/project
  → 规范化项目路径、remote 名和 revision
  → 对源码路径做最长前缀匹配
  → 应用 project 覆盖 default 的 remote/revision
  → 确定性拼接仓库 URL
  → 输出 resolved / version_mismatch / ambiguous / unresolved / needs_review
```

OpenGrok 常见的 `/openharmony/` 项目前缀会被识别，但不会写入 Manifest 项目的源码根路径。没有匹配、同长度冲突、remote 缺失或 revision 缺失时，结果明确进入待复核状态，不猜测仓库或 `master`。

## 2. 实现文件

- `libs/openant-core/core/source_locator/manifest_resolver.py`
  - `ManifestRemote`、`ManifestProject`、`ManifestDocument`；
  - `parse_manifest()` / `load_manifest()`；
  - `resolve_project()` 的最长前缀匹配；
  - `ManifestResolver.resolve()` 和 `RepositoryMapping`；
  - Manifest 内容 SHA-256 与 `revision:hash` 缓存键。
- `libs/openant-core/core/source_locator/__init__.py`
  - 导出 Manifest 解析和映射公共接口。
- `libs/openant-core/tests/source_locator/fixtures/manifests/ohos.xml`
  - 脱敏、可审阅的最小 Manifest 夹具。
- `libs/openant-core/tests/source_locator/test_manifest_resolver.py`
  - 21 项 Manifest、路径、版本和安全边界测试。

## 3. 具体映射例子

夹具中声明：

```xml
<remote name="gitcode" fetch="https://gitcode.com/openharmony" />
<default remote="gitcode" revision="OpenHarmony-6.1-LTS" />
<project name="startup_init" path="base/startup/init" />
```

输入 OpenGrok 路径：

```text
/openharmony/base/startup/init/services/param/linux/param_service.c
```

输出：

```text
project_name  = startup_init
source_root   = base/startup/init
matched_prefix= base/startup/init
repo_url      = https://gitcode.com/openharmony/startup_init
revision      = OpenHarmony-6.1-LTS
status        = resolved
```

如果同时存在：

```text
foundation/communication
foundation/communication/netmanager_base
```

路径 `foundation/communication/netmanager_base/services/a.cpp` 会选择第二个更长的前缀，而不是宽泛的 `communication` 项目。

## 4. 独立测试结果

执行：

```text
cd libs/openant-core
../../.venv/bin/pytest -q tests/source_locator/test_manifest_resolver.py
21 passed in 0.03s
```

同时执行源码定位器回归：

```text
../../.venv/bin/pytest -q tests/source_locator
93 passed in 0.08s
```

静态检查：

```text
../../.venv/bin/ruff check \
  core/source_locator/manifest_resolver.py \
  tests/source_locator/test_manifest_resolver.py \
  core/source_locator/__init__.py
All checks passed!
```

Python `compileall` 和 `git diff --check` 均通过。

覆盖内容包括：

- Manifest 默认 remote/revision 继承；
- project 级 remote/revision 覆盖默认值；
- `/openharmony/` OpenGrok 路径前缀；
- 最长前缀选择和同长度冲突；
- Manifest 无匹配时不猜仓库；
- remote 或 revision 缺失时 `needs_review`；
- 请求 revision 不一致时 `version_mismatch`；
- URL 用户名、密码、query、fragment、路径穿越和非 HTTP(S) 拒绝；
- DOCTYPE/ENTITY、错误根节点、缺字段和超大 Manifest 拒绝；
- Manifest 内容哈希和 revision 缓存键变化；
- 输出对象的 JSON 字段和待复核信息完整保留。

## 5. 设计边界

- 本阶段只解析已经提供的本地 XML；`include` 文件不会自动联网展开，而是记录警告；
- 仓库 URL 的 GitCode host/组织白名单、revision 最终策略留给 SL-03B；本阶段只做 URL 形状和基本安全校验；
- `status=resolved` 仅表示 Manifest 解析成功，不表示仓库已经存在、本地版本已验证或用户已经批准 clone；
- `verified` 默认为 `false`，后续 RepositoryManager 和 post-clone verifier 不能跳过；
- 映射结果没有触发网络请求，不会覆盖 `source_code_base` 中已有仓库。

## 6. 结论

SL-03A 已完成：源码路径现在能够通过 Manifest 的确定性最长前缀规则映射到项目名、remote、GitCode URL 和 revision；冲突、缺失和版本不一致会显式暴露给用户。下一阶段再增加 GitCode allowlist 和 revision 校验，之后才具备进入用户确认/安全 clone 流程的条件。
