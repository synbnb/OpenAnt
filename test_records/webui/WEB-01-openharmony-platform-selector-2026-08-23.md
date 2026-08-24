# WEB-01：Web UI OpenHarmony 平台选择与参数传递测试记录

## 1. 阶段目标

为本地 Web UI 增加平台选择能力，使交互扫描可以显式选择：

- `auto`：保持原有默认行为；
- `generic`：强制通用解析模式；
- `openharmony`：强制 OpenHarmony 平台解析和入口检测模式。

本阶段只修改 Web UI 参数链，不修改 Python 扫描器、LLM Prompt 或漏洞判定逻辑。

## 2. 修改前后逻辑

### 修改前

Web 表单只提交语言、Stage 2、动态测试和 library mode。Go 服务构造 Python 命令时不会传递 `--platform`，因此只能依赖 Python 扫描器的隐式 `auto` 模式。

### 修改后

1. Web 表单增加平台下拉框。
2. Go 服务端只接受 `auto`、`generic`、`openharmony` 三个值。
3. 空值兼容为 `auto`。
4. `auto` 不追加平台参数，保持历史命令行参数不变。
5. `generic` 追加 `--platform generic`。
6. `openharmony` 追加 `--platform openharmony`。
7. 平台值写入 Job 元数据，旧版没有该字段的历史任务仍可恢复。

## 3. 修改文件

- `apps/openant-cli/internal/server/server.go`
  - 增加平台白名单和输入校验；
  - 保存/恢复 Job 平台字段；
  - 将显式平台转换为 Python CLI 参数。
- `apps/openant-cli/ui/index.html`
  - 增加 `auto`、`generic`、`openharmony` 选择框。
- `apps/openant-cli/internal/server/platform_test.go`
  - 增加平台规范化、参数生成和非法请求测试。

## 4. 测试环境

| 项目 | 值 |
|---|---|
| 系统 | macOS arm64 |
| Go | go1.25.7 |
| 工具链 | `OpenAnt/.devtools/go1.25.7/go` |
| 模块 | `apps/openant-cli` |

## 5. 测试命令与结果

### 5.1 server 专项测试

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./internal/server -count=1 -v
```

结果：通过。

关键新增用例：

- 空平台值默认为 `auto`；
- `auto` 不生成平台参数；
- `generic` 生成 `--platform generic`；
- `openharmony` 生成 `--platform openharmony`；
- 未知平台 `android` 被拒绝；
- 非法平台请求不会创建 Job。

最终结果：

```text
ok github.com/knostic/open-ant-cli/internal/server 1.588s
```

### 5.2 Go CLI 全量回归

第一次在受限沙箱中运行时，已有 `cmd.TestProbeOpenAI_AcceptsValid` 因测试环境禁止 `httptest` 绑定回环端口而失败；未发现业务断言失败。随后在允许本机回环端口的测试环境中使用同一命令重跑。

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./... -count=1
```

结果：全部通过。

```text
ok github.com/knostic/open-ant-cli/cmd
ok github.com/knostic/open-ant-cli/internal/checkpoint
ok github.com/knostic/open-ant-cli/internal/config
ok github.com/knostic/open-ant-cli/internal/git
ok github.com/knostic/open-ant-cli/internal/languages
ok github.com/knostic/open-ant-cli/internal/models
ok github.com/knostic/open-ant-cli/internal/output
ok github.com/knostic/open-ant-cli/internal/python
ok github.com/knostic/open-ant-cli/internal/report
ok github.com/knostic/open-ant-cli/internal/server
ok github.com/knostic/open-ant-cli/ui [no test files]
```

### 5.3 CLI 构建验证

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go build \
  -ldflags "-X github.com/knostic/open-ant-cli/cmd.version=dev-platform-ui" \
  -o bin/openant ./main.go
./bin/openant version
```

结果：构建成功，版本命令成功输出：

```text
openant dev-platform-ui
  Go:     go1.25.7
  Python: 3.14.5
```

### 5.4 变更格式检查

```bash
git diff --check
```

结果：通过，无空白错误。

## 6. 尚未覆盖的内容

- 尚未启动真实浏览器进行手工点击测试；
- 尚未让 Web UI 对 OpenHarmony 仓库进行真实 LLM 扫描；
- Web UI 仍未暴露 `--no-context`、`--no-enhance`、`--llm-reachability` 等高级选项；
- Stage 2 和动态测试仍按原有 Web UI 默认选项运行。

## 7. 结论

WEB-01 已完成。Web UI 现在可以显式选择 OpenHarmony 平台，并且服务器会安全地将该选择传递到 Python 扫描器；默认 `auto` 行为保持兼容。未发现 Go CLI 回归失败。

