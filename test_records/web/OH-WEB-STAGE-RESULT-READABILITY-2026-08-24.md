# OH-WEB-STAGE-RESULT-READABILITY-2026-08-24

## 本次改动

修复扫描详情页“关键结果”卡片的 OpenHarmony 字段可读性：

- 不再把嵌套 JSON 对象直接转成字符串，因此不会出现 `[object Object]`。
- `dataset.json` 的 OpenHarmony 范围拆分为平台、源码范围、文件覆盖率、组件清单数和构建文件数等字段。
- 外部输入源和信任边界显示中文名称，例如“Binder IPC 数据”“IPC 调用者身份”，并解释“不可信”“半可信”等信任级别。
- 输入源中的英文说明也会翻译为中文，例如“由调用者控制的 MessageParcel 字段和事务载荷”。
- 三条漏洞判定标准在中文界面显示中文解释；原始英文值仍保留在“原始 JSON”视图中，未修改产物文件。
- 嵌套对象使用递归摘要，常见字段（文件路径、文件角色、组件、构建目标、输入说明等）显示中文标签。
- 对构建文件、组件清单、攻击者画像、统一问题等集合优先显示数量，不在阶段卡片中展开冗长对象；其他摘要统一限制长度。
- 攻击者画像保留数量摘要，并在其下方增加默认收起的原生折叠详情；展开后可查看身份、能力、限制、入口和潜在影响。
- 攻击者画像详情卡片改为横跨结果区域整行，桌面端标签列固定宽度，移动端标签与内容上下排列，避免每行只能显示几个字。

## 验证范围

使用历史扫描 `757e4c605b956250` 的真实产物结构核对了以下路径：

- `dataset.json.metadata.openharmony_scope`：包含 `platform`、`source_scope`、`coverage` 和 `build_metadata`。
- `application_context.json.input_sources`：包含 Binder IPC 数据和 IPC 调用者身份的嵌套说明。
- `application_context.json.trust_boundaries`：包含 `untrusted` 和 `semi_trusted` 信任级别。
- `application_context.json.vulnerability_criteria`：包含 3 条英文安全判定规则。

## 测试记录

| 检查项 | 结果 |
| --- | --- |
| 扫描页 JavaScript 语法检查（`node --check`） | 通过 |
| `go test ./internal/server` | 通过 |
| `go test -race ./internal/server` | 通过 |
| 友好视图不再包含 `[object Object]` 字面量 | 通过（模板检查） |
| 摘要压缩冒烟检查：构建文件、攻击者画像、统一问题 | 分别显示“2 个构建文件”“2 个攻击者画像”“1 个统一问题” |
| 攻击者画像折叠详情冒烟检查 | 通过；可展开显示标识、位置、说明、能力、限制、入口和影响 |
| 原始 JSON 数据写入逻辑 | 未改动 |

## 预期页面效果

在扫描详情页选择“源码解析”或“应用上下文”阶段后，关键结果卡片应显示中文字段和值。切换到英文后，字段标签和通用值切换为英文；点击“独立查看”或“原始 JSON”仍可审阅完整原始字段和值。
