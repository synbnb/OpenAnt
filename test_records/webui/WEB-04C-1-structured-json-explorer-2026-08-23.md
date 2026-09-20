# WEB-04C-1 测试记录：完整 JSON 结构化浏览器

日期：2026-08-23  
阶段：WEB-04C-1（JSON 产物完整字段浏览）  
范围：扫描详情页的 JSON 产物查看，不包含动态测试和调用图节点可视化

## 1. 本阶段目标

让用户可以在扫描详情页中以可读方式审阅 JSON 产物，同时保留原始 JSON 入口：

- 产物列表中的 `.json` 文件增加“友好查看”按钮；
- 对 `dataset.json`、`dataset_enhanced.json`、`analyzer_output.json`、`results.json`、`results_verified.json`、`pipeline_output.json` 等集合型产物提供列表、搜索、筛选和分页；
- 点击单个单元、函数或结果后按需读取完整对象，字段以可展开树展示；
- `analyzer_output.json` 的 `functions`、`call_graph`、`reverse_call_graph` 都可以独立切换和分页，避免调用图字段只能通过原始 JSON 查看；
- 任意其他 JSON 产物以完整字段树显示；
- 用户可以随时切换回原始 JSON，或在新标签页打开原始文件。

## 2. 逻辑变化

### 原逻辑

阶段产物列表只显示说明和“查看原始文件”链接。用户需要自行阅读完整 JSON，无法直接搜索单元、定位函数、筛选入口或查看单个对象的完整字段。

### 修改后逻辑

浏览器访问新的只读接口：

```text
GET /scan/{scan_id}/explore/{artifact}.json
```

接口先检查扫描任务、产物白名单、常规文件类型和文件大小，再解析 JSON。集合型产物只返回轻量列表行，默认每页 40 项，最多允许 200 项；`q`、`language`、`unit_type`、`verdict`、`entry_point`、`reachable` 等条件在后端过滤。点击某行后使用 `item` 参数再次请求完整对象，不把全部对象一次性塞入页面。

对于一个 JSON 根对象中的多个大集合，接口返回 `available_collections`。当前实现对 `analyzer_output.json` 暴露：

```text
functions
call_graph
reverse_call_graph
```

页面提供集合切换按钮。集合字段不会重复放入每个分页响应，但可以通过集合切换完整浏览，因此不会为了性能丢失调用图数据。

前端字段树使用原生 `details/summary`，嵌套对象或数组只有在用户展开时才创建子节点；所有文本使用 `textContent` 写入，避免将源码或 JSON 当作 HTML 执行。

## 3. 修改文件

- `apps/vulnfounder-cli/internal/server/server.go`
  - 新增 `/scan/{id}/explore/{name}` 路由；
  - 增加安全 JSON 解析、白名单、大小限制、分页、筛选、集合切换和单项详情；
  - 增加 `available_collections`，支持函数表和两张调用图分别浏览。
- `apps/vulnfounder-cli/ui/scan.html`
  - 增加友好视图/原始 JSON 切换；
  - 增加搜索、语言、单元类型、结论、入口、可达筛选；
  - 增加分页、集合切换、单项详情、字段树懒展开和复制 JSON；
  - 增加中英文翻译及原有语言切换兼容。
- `apps/vulnfounder-cli/internal/server/artifact_test.go`
  - 增加数据集搜索、分页、位置和完整单元详情测试；
  - 增加 analyzer 函数表搜索和调用图集合切换测试；
  - 增加非 JSON、非法分页、非法布尔参数测试。
- `apps/vulnfounder-cli/internal/server/ui_i18n_test.go`
  - 增加结构化浏览器关键 DOM 和行为标记检查。

## 4. 自动化测试

### 4.1 前端 JavaScript 语法检查

命令：

```bash
sed -n '/<script>/,/<\\/script>/p' apps/vulnfounder-cli/ui/scan.html \
  | sed '1d;$d' \
  | node --check
```

结果：通过（退出码 0）。

### 4.2 Web 服务专项测试

命令：

```bash
cd apps/vulnfounder-cli
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./internal/server -count=1
```

结果：通过。

覆盖内容：

1. `dataset.json?q=OnRemoteRequest&entry_point=true&limit=1` 返回正确的总数、文件和行号；
2. 使用 `item` 获取单个单元时保留完整代码和嵌套字段；
3. `analyzer_output.json?q=OnRemoteRequest` 能从函数 map 中命中目标函数；
4. `collection=call_graph` 能独立分页浏览调用图边；
5. 非白名单/非 JSON、超大分页、非法布尔条件会被拒绝；
6. Web 模板解析、中文/英文切换和结构化浏览器 DOM 标记检查通过。

### 4.3 完整 Go 回归

命令：

```bash
cd apps/vulnfounder-cli
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./... -count=1
```

结果：通过。`cmd`、`internal/server`、配置、解析、报告和其它包均通过。

### 4.4 构建检查

命令：

```bash
cd apps/vulnfounder-cli
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go build ./...
```

结果：通过。

## 5. 浏览器运行时验证限制

本环境中的 Playwright 包可以加载，但没有安装 Chromium 可执行文件，启动无头浏览器时报缺少：

```text
Executable doesn't exist ... chrome-headless-shell
```

因此本记录没有把静态检查冒充成截图或真实点击测试。用户本地启动 Web 服务后，应重点手工验证：

1. 在 `dataset.json` 上点击“友好查看”，搜索 `OnRemoteRequest`；
2. 点击某个单元，确认完整代码、metadata、platform_context 等嵌套字段都能展开；
3. 在 `analyzer_output.json` 中切换 `functions`、`call_graph`、`reverse_call_graph`；
4. 点击下一页和上一页，确认列表不会一次性加载全部函数；
5. 切换“原始 JSON”和“友好视图”，确认两者内容对应；
6. 切换中文/英文，确认新增控件文字和搜索占位符同步切换；
7. 打开浏览器开发者工具，确认上述操作没有 JavaScript 异常或 4xx/5xx 请求。

## 6. 已知边界

- 当前阶段没有实现调用图的节点拖拽、缩放和递归展开，这属于后续 WEB-04C-2；本阶段已提供 `call_graph` 和 `reverse_call_graph` 的完整分页数据入口。
- JSON 产物超过服务端既有的 8 MiB 查看上限时会返回 413，需要后续增加流式/下载模式；在上限以内，后端仍会解析一次 JSON，但页面不会一次性创建全部 DOM。
- 这次修改没有改变 OpenHarmony 入口识别、调用图生成、LLM 可达性或动态测试逻辑，只改进结果审阅方式。
