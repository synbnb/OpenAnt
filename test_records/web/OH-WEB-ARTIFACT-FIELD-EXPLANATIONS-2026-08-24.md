# OH Web 独立产物查看器字段解释补全记录

日期：2026-08-24

## 修改目标

独立产物查看器中，部分字段使用“暂未登记专用解释；保留原始字段和值。”作为统一提示，用户无法理解解析统计、平台画像、调用图元数据和模型用量等字段的含义。

## 修改内容

- 在 `apps/openant-cli/ui/artifact-view.html` 增加实际 OpenHarmony 产物字段的中文、英文名称和专用说明，覆盖：
  - 文件范围与解析统计；
  - bundle.json、GN、IDL、SA、Binder IPC、HDF 平台信息；
  - 调用图节点属性和图统计；
  - 数据集标注、上下文增强和 Agent 统计；
  - Token、费用、阶段耗时和报告路径；
  - 应用上下文、攻击者画像、信任边界和漏洞发现字段。
- 保留原始字段名（代码样式）和原始值，中文说明只作为辅助信息，不改变 JSON 内容。
- 对未来新增字段增加语义兜底：根据 snake_case/camelCase 字段名生成中文标题和用途说明；动态函数、宏、原型和路径键会标记为“动态条目”，不再显示“暂未登记专用解释”。
- 保留“原始 JSON”查看模式，方便逐字段核对。

## 验证

执行目录：`/Users/shiyu/学习/hyl/new/OpenAnt/apps/openant-cli`

```text
node --check <(awk 'BEGIN{p=0} /<script>/{p=1;next} /<\/script>/{p=0} p' ui/artifact-view.html)
```

结果：通过。

```text
GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go test ./internal/server
```

结果：通过。新增测试检查扩展字段映射、动态字段说明和旧占位提示已移除。

```text
GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go test -race ./internal/server
```

结果：通过。

Web 服务已重新构建并重启。通过
`/scan/757e4c605b956250/artifact-view/dataset_enhanced.json?lang=zh-CN`
验证页面返回 HTTP 200，页面源码中旧提示出现次数为 0，并包含新增的 `cost_amount`、`reachability_filter_applied` 和动态字段解释逻辑。
