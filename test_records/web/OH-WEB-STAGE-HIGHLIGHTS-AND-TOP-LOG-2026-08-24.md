# OH Web 阶段关键结果与顶部运行日志改造记录

日期：2026-08-24

## 修改目标

扫描详情页原来主要依靠阶段产物的独立 JSON 查看器了解结果，运行日志也位于右侧阶段内容栏中。本次改造让用户先在页面顶部看到完整运行进展，并在选择阶段后直接看到该阶段产物中筛选出的关键结果。

## 修改内容

### 1. 页面顶部运行日志

- 将运行日志从 `.scan-content` 中移出，放到页面级内容的最顶部；
- 日志现在横跨阶段菜单和详情区域，不再随着阶段菜单滚动或隐藏；
- 桌面端日志窗口高度从 340px 增加到 460px，移动端为 360px；
- 增加“自动跟随最新输出”提示，保留实时 SSE 日志和原有颜色分类。

### 2. 阶段关键结果卡片

每个阶段详情新增“关键结果”区域，只选择高信号字段，不把完整 JSON 搬到页面中：

- 源码解析：平台识别置信度、文件覆盖、数据集单元数、调用函数数和调用边数；
- 应用上下文：应用类型、置信度、远程触发要求、攻击者画像、输入源和信任边界；
- LLM 可达性：入口候选、外部输入、跨进程信号和采用状态；
- 上下文增强：增强单元数、增强模式、分类统计和 Agent Token 用量；
- 漏洞分析：模型、服务商、漏洞候选、安全、受保护和待定数量；
- 结果验证：验证记录、一致/不一致和确认漏洞数量（字段存在时展示）；
- 汇总输出：最终漏洞、安全、待定、可达单元和统一问题数量；
- 动态测试：状态、验证记录、观察结果和执行步骤（产物存在时展示）；
- 报告生成：扫描总量、最终判定、已完成/跳过阶段和报告输出路径。

每组卡片标注来源文件名，字段标题使用中文（英文模式使用英文），字段值醒目显示；完整字段仍可通过“独立查看”或“原始 JSON”查看。

## 测试

执行目录：`/Users/shiyu/学习/hyl/new/VulnFounder/apps/vulnfounder-cli`

```text
GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go test ./internal/server
```

结果：通过。

```text
GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go test -race ./internal/server
```

结果：通过。

```text
node --check <(awk 'BEGIN{p=0} /<script>/{p=1;next} /<\/script>/{p=0} p' ui/scan.html)
```

结果：通过。

Web 已重新构建并重启。访问历史扫描
`http://127.0.0.1:18080/scan/757e4c605b956250`
返回 HTTP 200，确认页面包含全宽顶部日志、460px 日志窗口、阶段关键结果区域和按产物文件读取逻辑；该扫描的 `/pipeline` 和 `/artifacts` 接口也均正常返回。
