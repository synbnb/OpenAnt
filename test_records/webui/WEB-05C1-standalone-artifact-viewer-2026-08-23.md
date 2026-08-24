# WEB-05C1 独立产物查看窗口测试记录

日期：2026-08-23  
阶段：Web/产物查看阶段 C1

## 本阶段目标

将扫描详情页中 JSON 产物的“友好查看”入口改为独立子窗口，并保留弹窗被浏览器拦截时的原页面降级入口。本阶段只建立独立查看容器和安全访问路径，不提前实现各类 JSON 的中文字段表单或调用图节点布局。

## 修改内容

- 新增 `apps/openant-cli/ui/artifact-view.html` 独立产物查看页面。
- 将该页面加入 Go embed，并由服务端解析、渲染。
- 新增 `GET /scan/{id}/artifact-view/{name}` 路由。
- 路由复用扫描任务校验、产物白名单和禁止符号链接检查，不把大 JSON 直接嵌入 HTML。
- 扫描详情页的“独立查看”按钮通过 `window.open` 打开子窗口，并传递当前中英文界面选择。
- 子窗口暂时提供安全的结构化预览、原始 JSON 切换、新标签页打开和关闭窗口操作。
- 浏览器拦截弹窗时回退到原有页内探索器，避免产物无法查看。

## 自动化测试

### Go 服务端全量测试

命令：

```text
GOCACHE=/private/tmp/openant-gocache GOPATH=/private/tmp/openant-gopath \
  /Users/shiyu/学习/hyl/new/OpenAnt/.devtools/go1.25.7/go/bin/go test ./...
```

结果：通过。`cmd`、`internal/server`、`internal/report`、`internal/python` 等全部包通过。

新增覆盖：

- 独立查看模板可解析；
- 扫描详情页包含 `window.open`、独立查看 URL 和弹窗失败降级逻辑；
- 独立查看路由可返回 HTML 页面；
- 页面包含任务 ID、产物名、结构化视图和原始 JSON 视图；
- 未加入白名单的产物返回 404；
- 中英文语言切换入口仍存在。

### 实际二进制验证

已重新构建 `apps/openant-cli/bin/openant`，重启 `127.0.0.1:18080` Web 服务，并使用已有扫描任务 `9b7f539401760206` 的真实 `dataset.json` 验证：

- `/scan/9b7f539401760206/artifact-view/dataset.json?lang=zh-CN` 返回 200；
- 返回页面包含 `data-artifact-name="dataset.json"`、`structured-view` 和 `raw-view`；
- 扫描详情页包含 `/artifact-view/` 和 `window.open(`。

## 当前边界

本阶段的结构化预览仍是通用 JSON 树，字段中文解释和不同产物的表单化展示尚未实现；这属于阶段 C2。调用图节点、缩放和展开属于阶段 C3。
