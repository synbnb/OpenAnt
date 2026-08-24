# ENV-00 OpenAnt 项目独立开发环境记录

> 后续状态：ENV-00 记录的 Go 缺失项已在 `ENV-01-project-local-go-1.25.7-2026-08-21.md` 中补齐并完成全量回归；本文件保留当时的原始测试结论。

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | ENV-00：项目独立开发环境 |
| 日期 | 2026-08-21 |
| OpenAnt 基线 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| 操作系统 | macOS（Darwin，Apple Silicon） |
| 环境位置 | `/Users/shiyu/学习/hyl/new/OpenAnt/.venv` |
| 安装策略 | Python 3.11 venv；不复用 Conda base 或 `~/.openant/venv` |

## 2. 原项目环境逻辑

- Go CLI 首次运行时可以在 `~/.openant/venv/` 创建运行环境，并执行 `pip install -e <openant-core>`。
- 该自动安装不包含 `[dev]`，因此不会安装 pytest 和 Ruff。
- CI 使用 Python 3.11，执行 `pip install -r requirements.txt` 和 `pip install ".[dev]"`。
- CI 另外安装 JavaScript parser 的 `package-lock.json` 依赖并构建 Go parser。
- 当前仓库根 `.gitignore` 已排除 `.venv/`、`node_modules/` 和 Go parser 二进制。

本阶段按项目自身 venv 逻辑和 CI 依赖顺序建立独立开发环境，并将 openant 以 editable 模式指向当前源码。

## 3. 预检结果

| 项目 | 结果 |
|---|---|
| Python 3.11 | `/Users/shiyu/.local/bin/python3.11`，版本 3.11.15 |
| 系统 `python3` | 3.14.5；未用于本环境 |
| Node.js | 25.9.0 |
| npm | 11.12.1 |
| Go | 未安装，PATH 中无 `go` |
| 可用磁盘 | 约 154 GiB |
| 原 `.venv` | 不存在 |
| 原 `node_modules` | 不存在 |

版本差异：CI 使用 Node 22，本机为 Node 25.9.0。本阶段先通过锁文件安装和测试验证兼容性，不修改 `package-lock.json`。

## 4. Python 环境创建

命令：

```bash
cd /Users/shiyu/学习/hyl/new/OpenAnt
/Users/shiyu/.local/bin/python3.11 -m venv .venv
```

结果：成功。

```text
Python 3.11.15
pip 24.0
```

未主动升级 pip，避免与项目无关的环境漂移。

## 5. Python 依赖安装

### 5.1 运行依赖

命令：

```bash
.venv/bin/python -m pip install -r libs/openant-core/requirements.txt
```

第一次在受限网络环境中执行失败，错误为无法解析 PyPI 地址：

```text
Failed to establish a new connection: nodename nor servname provided
No matching distribution found for annotated-types==0.7.0
```

该错误是沙箱网络不可用，不是依赖版本不存在。获得网络权限后用相同命令重试，安装成功。

### 5.2 开发依赖和 editable 安装

命令：

```bash
.venv/bin/python -m pip install -e "libs/openant-core[dev]"
```

结果：成功安装 `openant 0.1.0`、pytest 和 Ruff；运行依赖满足项目声明。

环境验证：

| 检查 | 结果 |
|---|---|
| `.venv/bin/python --version` | Python 3.11.15 |
| `.venv/bin/python -m pytest --version` | pytest 9.1.1 |
| `.venv/bin/python -m ruff --version` | ruff 0.16.4 |
| `.venv/bin/openant --version` | openant 0.1.0 |
| `import openant` | 指向当前 `libs/openant-core/openant/__init__.py` |
| `.venv/bin/python -m pip check` | `No broken requirements found` |

## 6. JavaScript parser 依赖

命令：

```bash
cd libs/openant-core/parsers/javascript
npm ci
```

结果：成功。

```text
added 14 packages
audited 15 packages
found 0 vulnerabilities
```

顶层依赖：

- `@typescript/vfs@1.6.2`
- `ts-morph@27.0.2`
- `typescript@5.9.3`

`package.json` 中的 `npm test` 是占位脚本，会固定返回 `Error: no test specified`；因此没有把它当作有效测试。JavaScript parser 由 OpenAnt Python 测试套件覆盖。

## 7. 环境占用与 Git 隔离

| 路径 | 大小 | Git 状态 |
|---|---:|---|
| `.venv` | 179 MiB | 被 `.gitignore:5` 排除 |
| `libs/openant-core/parsers/javascript/node_modules` | 38 MiB | 被 `.gitignore:6` 排除 |
| `libs/openant-core/parsers/go/go_parser/go_parser` | 未生成 | 已有忽略规则 |

环境安装没有修改 lockfile、requirements、pyproject 或生产代码。

## 8. 隔离环境验证

### 8.1 Ruff

命令：

```bash
cd libs/openant-core
../../.venv/bin/python -m ruff check .
```

结果：退出码 `0`，`All checks passed!`。

这补齐了 OH-00A 原测试记录中因旧环境没有 Ruff 而未执行的检查。

### 8.2 OH-00A 外部五仓测试

命令：

```bash
OPENHARMONY_CORPUS_ROOT=/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
../../.venv/bin/python -m pytest tests/openharmony/test_corpus_manifest.py -v
```

结果：退出码 `0`，`2 passed in 0.13s`。

### 8.3 相关回归

命令：

```bash
../../.venv/bin/python -m pytest \
  tests/test_language_registry.py \
  tests/test_parser_adapter.py -v
```

结果：退出码 `0`，`61 passed in 0.09s`。

### 8.4 完整 Python 测试套件

命令：

```bash
OPENHARMONY_CORPUS_ROOT=/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
../../.venv/bin/python -m pytest tests/ -q
```

结果：退出码 `1`。

```text
1 failed, 2959 passed, 43 skipped in 46.06s
```

唯一失败：

```text
tests/conformance/test_F1_receiver_type_contract.py::test_go
FileNotFoundError: [Errno 2] No such file or directory: 'go'
```

结论：Python、JavaScript parser 依赖及 OH-00A 没有发现回归；完整测试尚未全绿的唯一原因是本机缺少 Go 工具链。没有跳过、修改或屏蔽该失败。

## 9. 未完成项与下一门禁

OpenAnt 有两个 Go 版本要求：

- Go CLI：`apps/openant-cli/go.mod` 要求 Go 1.25.7。
- Go parser：`libs/openant-core/parsers/go/go_parser/go.mod` 声明 Go 1.21。

当前 PATH 中没有 Go，因此尚未：

- 构建 `libs/openant-core/parsers/go/go_parser/go_parser`。
- 构建 `apps/openant-cli/bin/openant`。
- 运行完整 Go 测试。
- 使完整 Python 测试套件全绿。

安装 Go 会改变项目外的系统或工具链状态，超出本阶段已说明的 Python/Node 项目本地写入范围。应在用户确认安装方式后继续；安装完成后需要重新运行失败的 conformance test、完整 Python tests、Go parser tests 和 Go CLI tests，并更新本记录。

## 10. 阶段结论

项目独立 Python 3.11 开发环境和 JavaScript parser 依赖已成功建立，可用于后续 Python/OpenHarmony 开发与测试。Ruff、OH-00A 和相关回归均通过。

环境尚未达到“全工具链完成”状态，唯一明确阻塞项是 Go 未安装。下一步需要先协商 Go 1.25.7 的安装方式，不能把当前完整测试结果描述为全绿。
