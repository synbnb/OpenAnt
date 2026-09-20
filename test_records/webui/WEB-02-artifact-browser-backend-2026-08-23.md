# WEB-02：扫描产物浏览后端测试记录（第一小阶段）

## 1. 阶段目标

为 Web 页面后续展示扫描产物提供安全的后端接口。本阶段只增加接口和测试，不修改页面、不改变扫描流程、不启用动态测试。

## 2. 修改前后逻辑

### 修改前

Web 只能读取阶段状态接口、SSE 日志、HTML 报告和 Summary；`dataset.json`、应用上下文、平台画像、调用图和各阶段结果只能到磁盘手动查看。

### 修改后

新增两个只读接口：

- `GET /scan/{id}/artifacts`：返回固定白名单中已经生成的产物元数据；
- `GET /scan/{id}/artifact/{name}`：读取白名单中的单个产物。

允许浏览的文件包括阶段报告、`application_context.json`、`platform_profile.json`、数据集、调用图、分析结果、验证结果、`pipeline_output.json` 和动态测试结果。接口不暴露克隆仓库、任意路径或日志文件。

安全约束：

- 文件名必须匹配服务端固定白名单；
- 读取时复用 `openRegularInRoot`，拒绝符号链接和越界路径；
- 单个产物超过 8 MiB 时拒绝读取；
- JSON/Markdown 使用明确的响应 Content-Type；
- 未知任务和未知产物均返回 404。

## 3. 修改文件

- `apps/vulnfounder-cli/internal/server/server.go`
  - 注册产物列表和读取路由；
  - 增加产物白名单、元数据投影和安全读取逻辑。
- `apps/vulnfounder-cli/internal/server/artifact_test.go`
  - 测试列表与读取接口、白名单、未知任务、符号链接和超大文件拒绝。

## 4. 测试环境

| 项目 | 值 |
|---|---|
| 系统 | macOS arm64 |
| Go | 项目内 `.devtools/go1.25.7` |
| 模块 | `apps/vulnfounder-cli` |

## 5. 测试命令与结果

### 5.1 Web 服务专项测试

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./internal/server -count=1 -v
```

结果：通过。新增测试覆盖：

- 产物列表只返回白名单文件；
- 产物 JSON 可通过路由读取；
- 未知产物和未知任务返回 404；
- 符号链接产物被拒绝；
- 超过 8 MiB 的产物返回 413。

```text
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server 1.273s
```

### 5.2 Go 全量回归

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./... -count=1
```

结果：全部通过，包括 `cmd`、`internal/server`、`internal/python`、`internal/report` 等包。

### 5.3 变更格式检查

```bash
git diff --check
```

结果：通过，无空白错误。

## 6. 尚未覆盖内容

- 尚未修改 Web 页面展示产物列表；
- 尚未在浏览器中手工点击查看产物；
- 尚未实现 Web 分阶段启动/截止阶段控制；
- 动态测试仍未改造、未执行。

## 7. 结论

Web-02 后端第一小阶段完成。后续页面可以直接调用安全接口展示 OpenHarmony 平台画像、应用上下文、调用图和分析结果。
