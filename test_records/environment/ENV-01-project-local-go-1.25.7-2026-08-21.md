# ENV-01 项目本地 Go 1.25.7 安装与回归记录

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | ENV-01：项目本地 Go 1.25.7 |
| 日期 | 2026-08-21 |
| VulnFounder 基线 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| 操作系统 | macOS 26.5.1（Darwin，Apple Silicon/arm64） |
| Go 安装位置 | `/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/go1.25.7/go` |
| Go 缓存位置 | `/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/gopath`、`.devtools/gocache` |
| 安装策略 | 项目本地归档；不修改 Homebrew、系统 PATH 或 shell 配置 |

## 2. 原项目逻辑与本阶段逻辑

原项目存在两个相互独立的 Go 模块：

- `libs/vulnfounder-core/parsers/go/go_parser` 是由 Python 核心调用的 Go 源码解析器，`go.mod` 声明最低 Go 1.21。
- `apps/vulnfounder-cli` 是 VulnFounder 命令行入口，`go.mod` 精确声明 Go 1.25.7；Makefile 将 Git 版本写入二进制并输出到 `apps/vulnfounder-cli/bin/openant`。

ENV-00 没有发现系统 Go，因此完整 Python 测试中唯一失败是 `test_F1_receiver_type_contract.py::test_go` 找不到 `go`。

本阶段使用满足两个模块要求的 Go 1.25.7，并把工具链、`GOPATH`、模块缓存和构建缓存全部限制在项目 `.devtools/` 内。运行命令显式设置 `GOTOOLCHAIN=local`，防止 Go 自动切换或下载其他工具链。

## 3. 官方来源与完整性校验

下载文件：

```text
https://go.dev/dl/go1.25.7.darwin-arm64.tar.gz
```

Go 官方发布页公布的 SHA256：

```text
ff18369ffad05c57d5bed888b660b31385f3c913670a83ef557cdfd98ea9ae1b
```

本地计算结果：

```text
ff18369ffad05c57d5bed888b660b31385f3c913670a83ef557cdfd98ea9ae1b  go1.25.7.darwin-arm64.tar.gz
```

结果：完全一致。解压前还检查了归档成员，所有条目均位于单一 `go/` 顶层目录。

## 4. 安装与隔离验证

工具链身份：

```text
go version go1.25.7 darwin/arm64
GOVERSION=go1.25.7
GOOS=darwin
GOARCH=arm64
GOROOT=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/go1.25.7/go
```

仓库根 `.gitignore` 新增：

```gitignore
.devtools/
```

`git check-ignore` 已确认 Go 工具链、模块缓存与构建缓存均由该规则排除。环境占用：

| 路径 | 大小 |
|---|---:|
| `.devtools/go1.25.7` | 233 MiB |
| `.devtools/gopath` | 76 MiB |
| `.devtools/gocache` | 172 MiB |

没有修改系统 PATH、shell profile、Homebrew、`go.mod` 或 `go.sum`。

## 5. 模块依赖准备

两个模块均使用以下隔离变量：

```text
GOTOOLCHAIN=local
GOTELEMETRY=off
GOPATH=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/gopath
GOMODCACHE=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/gopath/pkg/mod
GOCACHE=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/gocache
```

- Go parser 执行 `go mod download`：成功，模块无外部依赖。
- CLI 执行 `go mod download`：成功，依赖按现有 `go.mod`/`go.sum` 下载到项目本地缓存。

## 6. Go parser 独立测试与构建

目录：`libs/vulnfounder-core/parsers/go/go_parser`

测试命令：

```bash
go test ./...
```

结果：退出码 `0`。

```text
ok  github.com/openant/go_parser  0.481s
```

构建命令：

```bash
go build -o go_parser .
```

结果：退出码 `0`，生成 3.7 MiB 的 macOS arm64 Mach-O 可执行文件。该产物由仓库原有 `.gitignore` 规则排除。

## 7. CLI 独立测试与构建

目录：`apps/vulnfounder-cli`

### 7.1 首次受限测试

首次在文件系统沙箱内运行 `go test ./...` 时退出码为 `1`，失败发生在：

```text
cmd.TestProbeOpenAI_AcceptsValid
httptest: failed to listen on a port
listen tcp6 [::1]:0: bind: operation not permitted
```

这是测试环境禁止本机回环端口监听，不是业务断言失败；未修改或跳过测试。

### 7.2 同命令允许回环监听后重跑

```bash
go test ./...
```

结果：退出码 `0`。`cmd` 以及 `internal/checkpoint`、`config`、`git`、`languages`、`models`、`output`、`python`、`report`、`server` 全部通过；无测试文件的包按 Go 原样报告。

### 7.3 构建

```bash
make build
```

结果：退出码 `0`。

```text
go build -ldflags "-X github.com/synbnb/vulnfounder/apps/vulnfounder-cli/cmd.version=2476527-dirty" -o bin/openant ./main.go
```

生成 16 MiB 的 macOS arm64 Mach-O 可执行文件，位于原项目约定的 `apps/vulnfounder-cli/bin/openant`，并由原有 `.gitignore` 排除。

在项目 Python venv 与本地 Go 同时进入 PATH 时：

```text
openant 2476527-dirty
  Go:     go1.25.7
  Python: 3.11.15
```

说明：CLI 的版本子命令是 `openant version`；一次使用 `openant --version` 的诊断返回“unknown flag”，随后按 CLI 帮助改用正确子命令，成功通过。

## 8. Python/Go 契约测试

命令：

```bash
cd libs/vulnfounder-core
../../.venv/bin/python -m pytest \
  tests/conformance/test_F1_receiver_type_contract.py::test_go -v
```

PATH 显式加入项目本地 Go，其余 Go 环境变量仍指向 `.devtools/`。

结果：退出码 `0`，`1 passed in 0.91s`。ENV-00 中唯一失败已被直接复验并消除。

诊断命令前半段曾从 `libs/vulnfounder-core` 误用仓库根相对路径检查两个二进制，产生两条无效的“文件不存在”输出；同一命令中的契约测试仍通过。随后从仓库根重新检查，两个文件均存在且均为 arm64 Mach-O。该操作失误不代表构建失败，也没有修改文件。

## 9. 完整 Python 回归

命令：

```bash
cd libs/vulnfounder-core
PATH=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/go1.25.7/go/bin:... \
GOTOOLCHAIN=local \
GOPATH=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/gopath \
GOMODCACHE=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/gopath/pkg/mod \
GOCACHE=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/gocache \
OPENHARMONY_CORPUS_ROOT=/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
../../.venv/bin/python -m pytest tests/ -q
```

结果：退出码 `0`。

```text
2969 passed, 34 skipped in 41.59s
```

跳过项由测试自身的平台、可选依赖或条件标记决定；本阶段未新增跳过、未屏蔽测试、未修改测试逻辑。

## 10. Git 与格式审计

- `git check-ignore`：`.devtools`、Go parser 二进制、CLI `bin/openant` 均被正确排除。
- `git diff --check`：退出码 `0`，没有空白错误。
- 本阶段唯一配置修改是仓库根 `.gitignore` 新增 `.devtools/`。
- 未修改任何 Go/Python/JavaScript 生产代码或依赖声明。

## 11. 阶段结论

项目本地 Go 1.25.7 已成功安装并完成完整性校验。Go parser 和 CLI 均成功测试、构建，Python/Go 契约测试已从 ENV-00 的缺失工具链失败转为通过，完整 Python 测试套件全绿。

项目独立开发环境现已包含 Python 3.11、Node 依赖和 Go 1.25.7，可以进入后续 OpenHarmony 适配小阶段。按照协作门禁，在用户审阅并同意前不开始 OH-00B。
