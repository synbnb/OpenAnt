# WEB-05C2 产物专用中文表单测试记录

日期：2026-08-23  
阶段：Web/产物查看阶段 C2

## 本阶段目标

在 C1 独立查看窗口的基础上，将 JSON 产物按类型渲染为中文字段表单，并保留原始 JSON 查看入口。大集合不一次性渲染全部内容，而是使用已有探索接口分页，点击记录后再请求完整详情。

## 修改内容

- 独立窗口增加中文/英文字段目录：字段标题、原始字段名、用途说明和实际值同时显示。
- 增加通用表单组件，支持字符串、数字、布尔值、空值、数组、嵌套对象、源码和长文本。
- `dataset.json`、`dataset_enhanced.json`：按函数单元分页，展示文件位置、入口状态、可达性、调用关系、平台上下文和模型上下文。
- `analyzer_output.json`：按函数索引分页，展示函数签名、源码位置和原生分析字段。
- `call_graph.json`：支持函数、正向调用图和反向调用图集合切换；节点图布局留到 C3。
- `results.json`、`results_verified.json`、`pipeline_output.json`：按结果/发现分页，展示判定、置信度、CWE、分析理由、攻击向量和验证信息。
- `platform_profile.json`、`application_context.json`：按平台画像、威胁模型和信任边界分组展示。
- 各阶段 `*.report.json`：展示状态、时间、耗时、Token、费用、输入、输出、摘要和错误。
- 将真实扫描中此前未出现在 Web 列表的 `call_graph.json`、`report-data.report.json`、`pipeline_results.json`、`scan_results.json` 加入安全白名单。
- 未登记字段不会被丢弃，会保留原字段名、原值，并显示“暂无专用解释”。

## 自动化测试

### Go

命令：

```text
GOCACHE=/private/tmp/openant-gocache GOPATH=/private/tmp/openant-gopath \
  /Users/shiyu/学习/hyl/new/VulnFounder/.devtools/go1.25.7/go/bin/go test ./...
```

结果：通过。服务端、命令行、报告、Python 桥接等全部 Go 包通过。

新增/更新覆盖：

- 产物专用字段目录和表单渲染函数存在；
- 数据集集合分页和详情接口仍可用；
- 独立窗口模板可解析；
- 新增生成 JSON 白名单项均有合法阶段和说明；
- 原始 JSON 路径、非法产物 404 和符号链接防护未回归。

### JavaScript 语法

命令：

```text
node -e "读取 artifact-view.html 的 script 并使用 new Function 校验"
```

结果：`artifact-view script syntax: ok`。

### 真实 Web 服务和真实扫描产物

使用已存在的 `sensors_medical_sensor` 扫描任务 `9b7f539401760206`，重建并重启 `127.0.0.1:18080` 后验证：

- 产物列表新增并返回 `call_graph.json`、`pipeline_results.json`、`scan_results.json`、`report-data.report.json`；
- `dataset.json` 探索接口返回 `kind=collection`、集合 `units`、总数 9 和分页记录；
- 真实 `dataset.json` 详情返回完整单元字段，包括 `code`、`platform_context`、`reachable` 和 `is_entry_point`；
- `call_graph.json?collection=functions` 返回 408 个函数记录；
- `platform_profile.json` 独立页面返回并包含平台检测、构建元数据和源码覆盖字段；
- 使用实际 Chromium 无头浏览器执行页面，确认页面 DOM 出现“中文字段表单”“函数源码”“平台检测”“构建元数据”等真实渲染结果。

## 当前边界

C2 已经完成按产物类型的中文表单展示，但调用图目前仍是函数/边集合列表。可缩放节点图、入口函数节点和向下调用链展开属于阶段 C3，不在本阶段修改调用图数据或构建算法。
