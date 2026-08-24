# OH-WEB-DISCLOSURE-CARDS-2026-08-24

## 变更目标

运行完成后的“漏洞披露报告”列表不再只显示 `VULNERABLE`。每个条目现在直接展示：

- 漏洞类型（例如 CWE-862）
- 对应源码文件路径
- 对应函数
- 漏洞简要描述
- 原有的判定标签和独立披露文件链接

完整 Markdown 披露文件仍可点击打开，未改变原始报告内容和访问路径。

## 实现记录

1. Web 服务端扩展 `GET /disclosures/{scanID}` 返回元数据字段：
   `vulnerability_type`、`file_path`、`function`、`summary`。
2. 服务端从既有披露 Markdown 的 `Type`、`Summary`、`Vulnerable Code` 段落提取信息，摘要限制长度并折叠空白，避免超大报告拖慢列表。
3. 文件读取沿用符号链接拒绝和 `O_NOFOLLOW` 保护；解析失败时只返回原有文件名和标签，不会阻断披露列表。
4. 前端以安全的文本节点渲染卡片，不把报告内容直接当作 HTML 执行，并补充中英文界面文案。

## 测试记录

| 检查项 | 命令或验证 | 结果 |
|---|---|---|
| Go 服务端单元测试 | `go test ./internal/server` | 通过 |
| Go 竞态测试 | `go test -race ./internal/server` | 通过 |
| Go CLI 全量测试 | `go test ./...` | 通过 |
| 模板解析 | `TestWebTemplatesParseAfterRedesign` | 通过 |
| 披露元数据解析 | `TestParseDisclosureMetadata` | 通过 |
| 符号链接保护 | `TestDisclosureMetadataFromFileRejectsSymlink` | 通过 |
| 前端 JavaScript 语法 | `node --check` 提取的 `scan.html` 脚本 | 通过 |
| 历史扫描接口实测 | `GET /disclosures/ecad4bdd3d5f9ae8` | 返回漏洞类型、文件路径、函数和摘要字段 |

## 兼容性

该改动只读取扫描目录中已经生成的披露文件，因此历史扫描无需重新执行。若某个旧文件缺少对应 Markdown 段落，页面会显示“未提供”，同时仍保留打开完整披露文件的入口。
