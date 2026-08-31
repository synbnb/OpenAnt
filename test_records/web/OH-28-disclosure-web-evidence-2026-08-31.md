# OH-28：漏洞披露 Web 卡片证据展示测试记录

日期：2026-08-31

## 本阶段目标

验证扫描详情页的“漏洞披露报告”区域能够在保留原始 Markdown 链接的同时，直接展示：

- 漏洞对应的 CWE、文件、函数和代码行号；
- 扫描版本或提交版本；
- 修复状态（已生成修复代码、已有修复建议、证据不足待人工处理）；
- source → sink 摘要和有限的调用链节点；
- 没有新字段的历史扫描仍能正常显示，不因缺少 `pipeline_output.json` 或
  `report_context` 而失败。

## 原项目逻辑

后端 `/disclosures/{id}` 只读取披露 Markdown，提取漏洞标题、类型、文件、函数和摘要。
前端把每条结果渲染为一个链接卡片，行号、版本、修复状态和调用链需要用户打开完整文件后
自行查找。

## 修改后逻辑

后端在已知扫描目录内安全读取 `pipeline_output.json`，按照披露文件的序号关联对应 finding，
优先使用结构化位置、CWE、仓库版本和 `report_context`；同时从 Markdown 解析同名字段作为
历史扫描兼容回退。列表响应只保留调用链节点的函数、文件、行号和角色，不传输源码正文。

前端将卡片拆分为“摘要链接”和“证据与调用链”折叠区，所有不可信字段通过 `textContent`
写入；语言切换时会重新渲染卡片。打开摘要链接仍然可以查看完整 Markdown。

## 自动化测试

1. `go test ./...`（目录：`apps/openant-cli`）
   - 结果：通过；服务端、报告、配置、SSE、模板等测试全部通过。
2. 新增 `TestDisclosureListIncludesEvidenceContext`
   - 使用带 `pipeline_output.json`、`report_context` 和披露 Markdown 的临时扫描目录；
   - 验证 CWE、文件、函数、行号、版本、修复状态、source→sink 和两个调用链节点均被返回。
3. 更新 `TestScanPageProvidesDisclosureFindingCards`
   - 验证新的字段键、折叠证据区域、调用链渲染函数和中英文文案存在。
4. Node inline script 编译检查
   - 从 `ui/scan.html` 提取内嵌脚本并用 `new Function` 编译；
   - 结果：`compiled 1 inline script`。
5. `git diff --check`
   - 结果：通过，无空白错误。

## 结论

本阶段 Web 展示改造通过。旧扫描只显示原有字段时仍可降级运行，新扫描可以在卡片内直接
定位问题位置、版本和有限调用链；源码正文和完整证据仍由独立披露页提供。
