# WEB-02：扫描产物浏览页面测试记录（第二小阶段）

## 1. 阶段目标

将上一小阶段新增的扫描产物接口接入扫描详情页，让用户可以在 Web 中直接查看扫描器生成的阶段报告、平台画像、应用上下文、调用图和分析结果。

## 2. 修改前后逻辑

### 修改前

后端已经提供 `/scan/{id}/artifacts` 和 `/scan/{id}/artifact/{name}`，但页面没有调用它们，用户仍需手动访问接口或进入磁盘目录。

### 修改后

- 扫描详情页增加 `Scan artifacts` 区域；
- 页面显示产物名称、分类、大小和更新时间；
- 每个产物提供新标签页查看链接；
- 扫描运行期间每 1.5 秒刷新一次产物列表，扫描结束后再刷新一次；
- 页面使用 `textContent` 渲染名称和元数据，不把接口返回内容当作 HTML；
- 查看链接由固定的同源路径和 URL 编码后的白名单文件名构造，不直接注入接口返回的 URL；
- 没有产物时显示明确的空状态，不影响原有 SSE 日志和阶段进度显示。

## 3. 修改文件

- `apps/openant-cli/ui/scan.html`
  - 增加产物列表样式和 HTML 容器；
  - 增加产物轮询、格式化和安全渲染逻辑。

## 4. 测试环境

| 项目 | 值 |
|---|---|
| 系统 | macOS arm64 |
| Go | 项目内 `.devtools/go1.25.7` |
| Node.js | `/opt/homebrew/bin/node` |
| 模块 | `apps/openant-cli` |

## 5. 测试命令与结果

### 5.1 JavaScript 语法检查

```bash
python3 -c 'from pathlib import Path; import re; s=Path("apps/openant-cli/ui/scan.html").read_text(); print(re.search(r"<script>(.*?)</script>", s, re.S).group(1))' | node --check
```

结果：通过，无 JavaScript 语法错误。

### 5.2 页面静态契约检查

检查页面包含产物容器、接口请求、URL 编码和 `textContent` 安全渲染。

结果：

```text
WEB_02_UI_STATIC_OK artifact_panel=1 safe_text_render=1 filename_visible=1
```

### 5.3 server 专项回归

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./internal/server -count=1
```

结果：通过。嵌入 HTML 模板和后端产物接口相关测试均通过：

```text
ok github.com/knostic/open-ant-cli/internal/server 2.225s
```

### 5.4 变更格式检查

```bash
git diff --check
```

结果：通过，无空白错误。

## 6. 尚未覆盖内容

- 尚未启动真实浏览器进行点击验证；
- 尚未增加产物内容的页面内 JSON 格式化查看器，目前通过新标签页打开后端响应；
- 尚未实现 Web 分阶段启动/截止阶段控制；
- 动态测试仍未改造、未执行。

## 7. 结论

Web-02 页面第二小阶段完成。用户现在可以在扫描详情页看到已生成的扫描产物，并通过安全链接查看具体文件内容。
