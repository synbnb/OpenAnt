# CONFIG-01：项目内 LLM 配置统一测试记录

- 日期：2026-08-23
- 阶段：项目内配置解析与 Go/Python/Web 统一
- 目标：不设置 `XDG_CONFIG_HOME` 时，OpenAnt 仍从项目目录读取 LLM 配置；交付包不依赖 `/private/tmp`。

## 本阶段改动

1. Go 配置解析支持 `OPENANT_CONFIG_FILE`、项目内 `config/openant/config.json`，并兼容旧的 XDG/用户目录配置。
2. Python LLM 注册器采用相同优先级，并拒绝从扫描目标当前工作目录推导项目根目录。
3. Go 启动 Python 子进程时传递解析后的 `OPENANT_CONFIG_FILE`，避免两侧选择不同文件。
4. 当前本机配置已复制到 `config/openant/config.json`，权限为 `0600`；真实配置文件已加入 `.gitignore`。
5. 新增无密钥模板 `config/openant/config.example.json` 和使用说明。

## 测试命令与结果

### Go 配置层

```text
GOCACHE=.devtools/gocache GOPATH=.devtools/gopath go test ./internal/config
```

结果：通过。

- 显式 `OPENANT_CONFIG_FILE` 优先级：通过
- 项目内配置优先于旧 XDG 配置：通过
- 项目内文件不存在时回退旧 XDG 配置：通过
- 项目内路径作为新配置写入目标：通过

### Python LLM 注册器

```text
python -m pytest -q tests/test_llm_registry.py tests/test_llm_config_schema.py
```

结果：`36 passed`。

- 显式路径、项目内路径、旧用户路径优先级：通过
- 显式路径不存在时不误读其他凭据文件：通过
- v2 配置解析和全部阶段绑定校验：通过

### Go Python 子进程环境

```text
go test ./internal/python
```

结果：通过。

- 注入解析后的 `OPENANT_CONFIG_FILE`：通过
- 保留其他环境变量：通过
- 不把配置内容或 API Key 注入环境变量：通过

### 项目内文件检查

```text
openant config path
```

结果：输出项目内路径：

```text
/Users/shiyu/学习/hyl/new/OpenAnt/config/openant/config.json
```

配置摘要（不输出密钥）：

- `default_llm`: `openharmony-live-gpt`
- provider: `autodl-openai`，类型 `openai`
- 各阶段模型：`gpt-5.6-luna`
- 文件权限：`0600`
- `git check-ignore`：确认真实配置会被忽略

### Web 端到端检查

启动命令未设置 `XDG_CONFIG_HOME`：

```text
./apps/openant-cli/bin/openant serve --addr 127.0.0.1:18080
```

由于测试环境中 `18080` 不可绑定，服务自动选择了回环临时端口；读取首页结果显示：

- 配置名：`openharmony-live-gpt`
- provider：`autodl-openai (openai)`
- 模型：`gpt-5.6-luna`
- 凭据状态：`configured in config.json`
- 未回退到：`openant-default / anthropic`

Web 进程已在测试结束后停止。

## 范围外回归检查

- Go 全量 `go test ./...`：通过。
- Python 全量测试在补齐项目内 Go 工具链后运行到 `2914 passed, 39 skipped, 22 failed`，随后因长时间运行的既有动态/模型测试手动停止。失败主要集中在 Python fixture 扫描得到 0 个文件、以及需要外部模型/运行环境的测试；本阶段新增的 LLM 配置定向测试全部通过，未发现配置解析回归。

## 安全说明

真实 `config.json` 含 API Key，只保留在当前本机的被忽略文件中；本记录、模板和代码均未包含密钥值。交付时应复制模板并由使用者自行填写凭据，不能把当前真实配置加入 Git 或公开压缩包。
