# WEB-03A：Web LLM Provider 状态显示测试记录

## 1. 阶段目标

修正 Web 首页将 LLM 凭据字段固定显示为 `Anthropic API Key` 的问题，使页面能够反映当前实际生效的 v2 provider、模型和 Base URL，同时保证 API Key 不进入 HTML。

## 2. 修改前后逻辑

### 修改前

- `index.html` 无条件显示 `Anthropic API Key`。
- 后端只识别旧版顶层 `api_key`；新版 `llm_providers` 配置不会被页面说明。
- 即使当前配置实际使用 OpenAI-compatible provider，用户也容易把密钥填入错误的 Anthropic 字段。

### 修改后

- 后端读取 `default_llm`、活动配置的 phase 绑定和 provider 元数据。
- 首页显示配置名、provider 名称、provider 类型、Base URL、模型绑定和凭据状态。
- 仅显示“已在 config.json 配置”或对应环境变量名称，不显示密钥值。
- 使用 v2 provider 配置时隐藏旧版 API Key 输入框，并提示凭据来源。
- 没有 v2 配置时保留 `LLM API Key (legacy Anthropic mode)`，兼容旧版 Anthropic 流程。

## 3. 修改文件

- `apps/vulnfounder-cli/internal/config/config.go`
  - 增加默认 LLM 配置名和非敏感 phase 摘要读取接口。
- `apps/vulnfounder-cli/internal/config/config_test.go`
  - 增加默认配置回退和 phase 摘要测试。
- `apps/vulnfounder-cli/internal/server/server.go`
  - 增加 provider-aware LLM 状态构建逻辑。
  - 只向模板传递非敏感状态。
- `apps/vulnfounder-cli/internal/server/llm_status_test.go`
  - 覆盖 OpenAI-compatible v2 配置和旧版配置两种页面渲染路径。
- `apps/vulnfounder-cli/ui/index.html`
  - 替换固定 Anthropic 字段，增加配置状态和 phase 模型绑定展示。

## 4. 测试环境

| 项目 | 值 |
|---|---|
| 系统 | macOS arm64 |
| Go | 项目内 `.devtools/go1.25.7` |
| Node.js | 系统 Node.js |
| 模块 | `apps/vulnfounder-cli` |
| 测试配置 | 临时 XDG 配置目录，包含 `autodl-openai` / `gpt-5.6-luna`，密钥使用测试哨兵值 |

## 5. 测试命令与结果

### 5.1 配置与 Web 后端专项测试

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./internal/config ./internal/server -count=1
```

结果：通过。

```text
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/config  1.380s
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server  1.868s
```

覆盖内容：

- OpenAI-compatible provider 在页面中可见；
- `gpt-5.6-luna` 和 Base URL 可见；
- 页面不包含 `Anthropic API Key` 旧字段；
- 页面不包含测试密钥值；
- 无 v2 配置时旧版 Anthropic 输入框仍存在。

### 5.2 Web 页面 JavaScript 和静态契约检查

```bash
python3 -c 'from pathlib import Path; import re; s=Path("apps/vulnfounder-cli/ui/index.html").read_text(); print(re.search(r"<script>(.*?)</script>", s, re.S).group(1))' | node --check
python3 -c 'from pathlib import Path; s=Path("apps/vulnfounder-cli/ui/index.html").read_text(); checks={"llm_status": "LLM configuration" in s, "provider_summary": ".LLM.Providers" in s, "legacy_gate": ".LLM.ShowLegacyKey" in s, "credential_status": "CredentialStatus" in s, "phase_bindings": "Phase model bindings" in s}; assert all(checks.values()), checks; print("WEB_03A_UI_STATIC_OK", " ".join(f"{k}={int(v)}" for k,v in checks.items()))'
```

结果：通过。

```text
WEB_03A_UI_STATIC_OK llm_status=1 provider_summary=1 legacy_gate=1 credential_status=1 phase_bindings=1
```

### 5.3 全量 Go 回归

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./... -count=1
```

结果：通过。第一次在受限沙箱中运行时，既有 `httptest` 临时端口监听被系统拒绝；申请本机回环测试权限后全量通过：

```text
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/cmd
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/checkpoint
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/config
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/git
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/languages
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/models
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/output
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/python
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/report
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server
```

### 5.4 二进制构建和真实 Web 页面检查

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go build \
  -ldflags "-X github.com/synbnb/vulnfounder/apps/vulnfounder-cli/cmd.version=web-03a" \
  -o bin/openant ./main.go
./bin/openant version
```

结果：构建通过，版本输出：

```text
openant web-03a
  Go:     go1.25.7
  Python: 3.14.5
```

使用当前临时配置启动后，实际页面地址为：

```text
http://127.0.0.1:64795
```

页面检查结果包含：

```text
LLM configuration
Provider: autodl-openai (openai)
Credentials: not detected
gpt-5.6-luna
```

页面不再显示旧版 `Anthropic API Key` 输入框。

### 5.5 变更格式检查

```bash
git diff --check
```

结果：通过。

## 6. 当前服务状态

Web 服务已使用 `web-03a` 二进制重新启动，扫描历史目录保留。当前服务地址为 `http://127.0.0.1:64795`。

当前临时配置没有实际 OpenAI 密钥，因此页面显示 `Credentials: not detected`；这只影响真正发起 LLM 扫描，不影响页面和仓库选择功能测试。

## 7. 尚未覆盖内容

- 尚未实现仓库下拉选择；
- 尚未实现浏览器目录上传；
- 尚未实现 Web 内 provider/API Key 配置表单；
- 动态测试仍未改造、未执行。

## 8. 结论

Web-03A 完成。当前 OpenAI-compatible 配置会在首页正确显示，不再误导用户填写 Anthropic API Key；旧版 Anthropic 配置仍保持兼容。
