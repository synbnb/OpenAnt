# WEB-05C4 调用图深度控制测试记录

日期：2026-08-23  
阶段：Web/产物查看阶段 C4

## 本阶段目标

改善调用图的向下浏览体验，让用户能够直接选择展开层数，并在默认情况下看到比一层更完整的调用子图。本阶段只修改 Web 可视化，不修改原始 `call_graph.json`、Reachable 算法或 OpenHarmony 间接调用边恢复逻辑。

## 原逻辑

- 页面加载和入口切换时，调用图深度固定为 1。
- 用户只能通过“展开一层”按钮逐层增加深度。
- 可视化最多保留 160 个节点，但页面没有直接选择层数的控件。

## 修改后逻辑

- 默认展开深度改为 3 层。
- 工具栏增加“查看层数”下拉框，可选择 1～8 层。
- 入口切换时重置为默认 3 层。
- “展开一层”和“收起一层”按钮仍然可用。
- 继续限制最多 160 个节点，避免高连接度调用图阻塞浏览器。
- 深度控制只沿 `call_graph.json` 中已经存在的边递归，不凭空补充缺失的 `Stub → handler` 边。

## 修改文件

- `apps/vulnfounder-cli/ui/artifact-view.html`
  - 增加深度选择控件和中英文文案；
  - 增加默认深度、最大深度和节点上限常量；
  - 入口切换和深度选择事件统一更新图状态。
- `apps/vulnfounder-cli/internal/server/ui_i18n_test.go`
  - 增加深度选择器和默认深度标记测试。

## 自动化测试

### 1. 内嵌脚本与模板标记

命令：

```text
node - <<'NODE'
const fs = require('fs');
const html = fs.readFileSync('apps/vulnfounder-cli/ui/artifact-view.html', 'utf8');
const match = html.match(/<script>([\\s\\S]*?)<\\/script>/);
if (!match) throw new Error('artifact-view script missing');
new Function(match[1]);
for (const marker of ['id="graph-depth-select"', 'GRAPH_DEFAULT_DEPTH = 3', 'GRAPH_MAX_DEPTH = 8']) {
  if (!html.includes(marker)) throw new Error('missing marker: ' + marker);
}
console.log('artifact-view depth control and script syntax: ok');
NODE
```

结果：通过。

```text
artifact-view depth control and script syntax: ok
```

### 2. Go 全量测试

工作目录：`apps/vulnfounder-cli`

命令：

```text
GOCACHE=/private/tmp/openant-gocache GOPATH=/private/tmp/openant-gopath \
  /Users/shiyu/学习/hyl/new/VulnFounder/.devtools/go1.25.7/go/bin/go test ./...
```

结果：通过。`cmd`、`internal/server`、配置、报告、Python 调用和其他 Go 包均通过。

说明：在受限沙箱中第一次运行时，`cmd` 包的 `httptest` 因无法绑定临时回环端口而失败；允许本机测试监听后使用同一命令重跑，全部通过。

### 3. 真实 Web endpoint

重新构建并重启 `127.0.0.1:18080` 服务后，请求：

```text
http://127.0.0.1:18080/scan/757e4c605b956250/artifact-view/call_graph.json?lang=zh-CN
```

结果：返回的新模板包含：

- `id="graph-depth-select"`；
- 默认选中 `3`；
- `GRAPH_DEFAULT_DEPTH = 3`；
- 深度选择变更事件。

### 4. 真实 Chrome DOM 验证

使用真实历史扫描任务 `757e4c605b956250`（`systemabilitymgr_samgr`）的 `call_graph.json` 和 `dataset.json`，通过本机 Chrome 无头模式加载页面。

观察到的页面状态：

```text
查看层数：3
7 节点 · 9 边 · 展开深度 3
```

截图验证显示工具栏、入口列表、SVG 调用图和节点详情在 1440px 宽度下正常排列，无明显溢出。

## 结果解释

本阶段能够让已有调用边递归显示到第 3 层或用户选择的更深层次，但不会修复当前 `systemabilitymgr_samgr` 中缺失的 `memberFuncMap_` 间接分发边。该问题仍属于 ADR-001 的后续调用边恢复阶段。

## 结论

WEB-05C4 已完成。调用图现在默认展示 3 层，并支持用户选择 1～8 层；节点上限和原始调用图数据保持不变。
