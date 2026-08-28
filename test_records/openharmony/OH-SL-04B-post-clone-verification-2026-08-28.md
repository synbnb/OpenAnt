# OH-SL-04B：拉取后源码验证与静态分析交接

日期：2026-08-28
阶段：源码定位前置流程（SL-04B）
模型调用：0 次
网络拉取：未执行（本阶段使用受控 Git runner 和临时目录夹具）
动态测试：未执行

## 1. 本阶段目标

SL-04A 的 `RepositoryManager` 已经能够在用户确认后安全拉取或复用 GitCode 仓库，
但“Git 命令成功”本身不能证明拉取出的目录就是用户确认的源码，也不能证明 OpenGrok
定位时引用的文件、符号和字符串仍然存在。本阶段增加一个只读的
`PostCloneVerifier`，只有所有必要检查通过时才生成 `SourceHandoff`，交给后续静态扫描。

## 2. 修改前后的逻辑

### 修改前

1. 仓库管理器返回 `cloned` 或 `reused` 后，调用方只能看到目标目录和 revision。
2. 没有统一的拉取后检查对象，调用方可能直接把目录交给扫描器。
3. 无法在结构化结果中区分“origin 不对”“HEAD 不对”“关键源码不存在”或“证据符号
   不存在”。

### 修改后

1. `RepositoryAcquisitionResult` 额外保存实际解析出的 `resolved_commit` 和经过策略
   校验的 `RepositoryMapping`，并继续保留原有字段的构造兼容性。
2. `PostCloneVerificationRequest` 接收有限数量的期望源码路径、辅助搜索路径、符号和
   字面量。所有路径先做长度、控制字符和路径穿越检查。
3. 验证器只允许目标目录位于项目内的 `source_code_base/<project>`，拒绝目录穿越、
   符号链接和非 Git/非成功拉取结果。
4. 使用只读 Git 命令检查 `origin`、`HEAD` 与确认的 GitCode 仓库、Manifest revision
   及 resolved commit 是否一致；没有已保存 commit 时只读解析 revision ref。
5. 源码文件只在仓库边界内读取，并设置最大读取字节数；记录 SHA-256、读取字节数和
   命中行号，不把完整源码写入验证结果。
6. OpenGrok 的完整路径和仓库相对路径都可作为辅助证据。完整路径会依据 Manifest
   `source_root` 转换为仓库内路径，避免把 `base/...` 重复拼到仓库目录下。
7. 任一检查失败都返回 `post_clone_verify_failed` 或 `rejected`，不生成交接对象；只有
   目录、origin、HEAD、关键源码文件、符号和字面量均通过时才生成
   `status=ready_for_analysis` 的 `SourceHandoff`。
8. 如果映射没有任何可验证的源码文件路径，也会失败闭环，不能产生空源码交接。

## 3. 涉及文件

- `libs/openant-core/core/source_locator/repository_manager.py`
  - 记录拉取/复用后的 commit 和 mapping；所有失败路径继续返回结构化结果。
- `libs/openant-core/core/source_locator/post_clone_verifier.py`
  - 新增请求、检查项、验证结果、源码交接对象和只读验证器。
- `libs/openant-core/core/source_locator/__init__.py`
  - 导出验证器及其结果类型，供后续 worker/Web 流程使用。
- `libs/openant-core/tests/source_locator/test_post_clone_verifier.py`
  - 新增 20 项边界、成功和失败闭环测试。

## 4. 独立测试记录

工作目录：`libs/openant-core`
Python 环境：项目独立环境 `.venv`

### 4.1 验证器单独测试

```text
../../.venv/bin/pytest -q tests/source_locator/test_post_clone_verifier.py
```

结果：`20 passed in 0.06s`。

覆盖内容包括：

- 正确 origin、HEAD、源码、符号和字面量生成 ready handoff；
- 缺少源码、符号或字面量不生成 handoff；
- origin、HEAD、revision ref 不一致时失败；
- 拉取失败、目录越界、仓库/源码（包括内部目标）符号链接、超大文件拒绝；
- OpenGrok 前缀路径正确归一化并搜索；
- acquisition mapping 不一致、无 source_path、非法输入和结果序列化。

### 4.2 源码定位器回归

```text
../../.venv/bin/pytest -q tests/source_locator
```

结果：`163 passed in 0.12s`。

### 4.3 静态检查和编译检查

```text
../../.venv/bin/ruff check core/source_locator tests/source_locator
../../.venv/bin/python -m compileall -q core/source_locator tests/source_locator
git diff --check -- \
  libs/openant-core/core/source_locator/repository_manager.py \
  libs/openant-core/core/source_locator/post_clone_verifier.py \
  libs/openant-core/core/source_locator/__init__.py \
  libs/openant-core/tests/source_locator/test_post_clone_verifier.py
```

结果：Ruff `All checks passed`；Python 编译无输出即成功；Git diff 空白检查通过。

## 5. 结果与边界

本阶段实现了“确认拉取 → 只读验证 → 明确交接/拒绝”的安全边界，后续扫描器不必再
猜测一个目录是否真的对应 OpenGrok/Manifest 证据。验证器不会修改仓库，不执行 shell
拼接，也不会把原始源码内容写入 JSON。

本阶段尚未把验证器接入 Web 的源码定位会话，也没有对真实网络仓库执行 clone；下一阶段
需要先讨论并实现 worker/会话层的调用、持久化和 Web 展示，再用一个小型真实仓库做端到端
验证。
