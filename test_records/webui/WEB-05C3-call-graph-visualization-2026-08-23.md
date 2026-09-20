# WEB-05C3 调用图可视化测试记录

日期：2026-08-23  
阶段：Web/产物查看阶段 C3

## 本阶段目标

在 C2 独立产物窗口中增加调用图的入口列表、向下可达子图、缩放、拖拽、展开/收起和节点详情，不修改调用图生成算法及 JSON 数据。

## 修改内容

- `call_graph.json` 和 `analyzer_output.json` 的独立查看窗口增加“调用图”视图。
- 入口函数优先读取真实 `dataset.json` 中的 `is_entry_point=true` 标记，并显示入口判定依据；只有没有入口标记时才从反向调用图推断图根。
- 从 `call_graph` 的真实正向边构建 BFS 子图，默认展示一层下游节点。
- 入口列表支持切换不同入口；默认优先选择存在下游边的入口，避免打开页面时只看到孤立入口。
- SVG 节点图支持：
  - 滚轮缩放；
  - 拖动画布；
  - 适配画布、放大、缩小；
  - 展开一层、收起一层；
  - 点击节点或使用键盘 Enter/Space 查看详情。
- 节点详情继续使用 C2 中文字段表单，包含函数名、文件行号、参数、正向调用边、反向调用者和平台上下文。
- 没有下游边的入口明确显示“暂无已解析的下游调用边”，不虚构调用关系。
- 通过 SVG 原生绘制，不引入新的第三方前端依赖。

## 自动化测试

### Go

命令：

```text
GOCACHE=/private/tmp/openant-gocache GOPATH=/private/tmp/openant-gopath \
  /Users/shiyu/学习/hyl/new/VulnFounder/.devtools/go1.25.7/go/bin/go test ./...
```

结果：通过。所有 Go 包通过，包含 Web 模板、产物路由、白名单和 C3 SVG 行为标记测试。

### JavaScript 语法

使用 `new Function` 校验 `artifact-view.html` 内嵌脚本，结果：

```text
artifact-view script syntax: ok
```

### 真实 OpenHarmony 扫描产物

使用真实扫描任务 `9b7f539401760206`（`sensors_medical_sensor`）的 `call_graph.json` 和 `dataset.json` 验证：

- 入口列表来自真实 `dataset.json`，包含 5 个入口函数；
- 默认优先选择 `MedicalSensorService::OnStart`，因为它存在真实下游边；
- 默认图显示 `4 节点 · 3 边 · 展开深度 1`；
- 真实下游节点包括：
  - `InitSensorList`
  - `InitDataCache`
  - `InitInterface`
- `analyzer_output.json` 使用同一逻辑也显示 `4 节点 · 3 边`；
- Chromium 无头浏览器执行后确认页面出现“入口函数”“向下调用图”“节点详情”“调用图”等界面元素。

## 当前边界

C3 只负责已有调用图数据的可视化。若 JSON 本身缺少 `Stub → handler` 边，页面会如实显示缺边，不会用前端规则或模型擅自补边；调用图补边算法属于后续分析阶段，不在本阶段修改。
