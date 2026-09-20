# Web 大型产物与阶段关键结果回归记录

## 目的

验证大型 OpenHarmony 扫描产物可以在 Web 中友好查看，并确认阶段详情使用真实产物字段，不再把缺失字段误显示为 `0`。

## 修复内容

- `dataset.json`、`dataset_enhanced.json`、`call_graph.json`、`results.json` 等大型 JSON 采用流式解析和分页返回，单次只保留当前页数据。
- 原始产物服务上限调整为 256 MiB；结构化浏览仍限制单页最多 200 条，避免把完整 JSON 注入浏览器。
- 阶段摘要改为读取 `pipeline_results.json` 和 `verify.report.json` 中的实际统计字段。
- 阶段关键结果改用 `/explore` 根摘要接口，不再为显示几个计数而下载整个大型 JSON。

## 测试环境

- Web 地址：`http://127.0.0.1:18080`
- 历史扫描：`347d903282351b35`
- 仓库：`multimedia_audio_framework`
- 真实产物目录：`~/.openant/webui/347d903282351b35`

## 自动化测试

执行：

```text
cd apps/vulnfounder-cli && go test ./internal/server
```

结果：通过。覆盖大型数据集流式分页、Symlink/超限保护、普通 JSON 结构化查看和 UI 模板回归检查。

## 真实 HTTP 验证

对历史扫描调用：

```text
GET /scan/347d903282351b35/explore/dataset.json?limit=1
GET /scan/347d903282351b35/explore/dataset_enhanced.json?limit=1
GET /scan/347d903282351b35/explore/call_graph.json?limit=1
GET /scan/347d903282351b35/explore/results.json?limit=1
```

四个请求均返回 HTTP 200。返回大小分别约为 130 KiB、130 KiB、0.9 KiB、0.8 KiB；`results.json` 不再把约 68.8 MiB 的 `code_by_route` 内联副本返回给浏览器。

`dataset.json` 结构化响应核对结果：

- 集合：`units`
- 当前页：2 条（测试请求使用 `limit=2`）
- 总记录数：273
- 根级 `statistics.total_units`：22,037（原始解析单元统计）

## 浏览器验证

通过 Chrome DevTools 访问历史扫描页面并分别选择“源码解析”和“结果验证”：

源码解析阶段显示：

```text
已解析 1,514 / 3,520 个文件；生成 273 个进入后续分析的单元，原生调用图包含 28,348 条调用边。
```

关键结果还显示：原始分析单元 22,037、入口函数 28、可达分析单元 273、可达性裁剪比例 98.8%。

结果验证阶段显示：

```text
验证结果：确认漏洞 3 个，一致 3 个，不一致 7 个，需人工复核 5 个。
```

`dataset.json` 独立查看页面显示“273 条记录”，可以加载列表和首条详情；页面未出现“读取产物失败，请稍后重试”。浏览器控制台未发现错误。

汇总输出阶段也已核对为真实值：统一问题 8 个、实际分析单元 263 个、可达单元 273 个；管线阶段结果显示函数 22,052 个、调用边 28,348 条。

## 结论

本次问题由两个独立原因造成：大型文件被 8 MiB 限制拦截，以及阶段摘要字段路径不匹配导致缺失值被当成 0。两处均已修复，原始 JSON 文件内容未被修改。
