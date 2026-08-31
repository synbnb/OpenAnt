# OH-22G-10B：LLM JSON 响应协议与重试修复测试记录

日期：2026-08-28  
对象：`hiviewdfx_hiview` 的 `GetLogParseSections` 间接分派入口  
模型：`autodl-openai / gpt-5.6-luna`  
配置：项目内 `config/openant/config.json` 的 `openharmony-live-gpt`

## 1. 问题与原逻辑

OH-22G-10 的首次批量实验选择了两个真实仓库入口。模型响应看起来是以 `{` 开头、以 `}` 结尾，
但 `evidence.text` 字符串中包含未经 JSON 转义的真实换行，严格 `json.loads` 失败。原实现的重试
会再次发送完全相同的提示，因此两次都可能失败；错误记录也没有响应形态信息。

诊断实验（OH-22G-10A）确认不是输出长度或 Markdown 围栏导致：响应无围栏、首尾括号完整，失败点
是 JSON 字符串中的非法真实换行。

## 2. 本阶段修改

1. 提示协议明确要求每个 `evidence.text` 为单行 JSON 字符串；源码多行只能引用一行，或使用 `\\n`
   转义，禁止把真实换行放进字符串。
2. 解析失败时，重试请求附加格式纠正提示和有限的上一轮校验错误；上下文仍来自同一份原始 worklist，
   不改变 site ID、候选集合或证据门槛。
3. 每次模型响应增加非敏感诊断元数据：字符数、SHA-256、首尾大括号偏移、JSON 候选长度、是否含
   Markdown 围栏；不保存响应正文，不做启发式 JSON 修复。
4. 解析器显式拒绝解析后仍包含 `\\n`/`\\r` 的 `evidence.text`，避免多行证据绕过协议。

## 3. 单元与静态测试

- 恢复器、注册上下文、证据行号解析相关测试：`21 passed`。
- 项目独立虚拟环境下完整 OpenHarmony 测试集：`169 passed, 2 skipped`。
- Ruff（`.venv/bin/ruff`）检查修改文件：`All checks passed`。
- 新增回归覆盖：
  - 首轮 `not-json` 后第二轮必须收到纠正提示；
  - `response_diagnostics` 必须记录 `invalid → valid`；
  - 多行 `evidence.text` 必须被拒绝；
  - 传输异常仍按原重试预算停止。

补充说明：核心库全量测试中有 7 项失败、23 项通过（其余被筛选未重跑）。失败项均为既有
环境/工作树问题，与本阶段文件无关：1 项依赖系统未安装 `go`；4 项把刚解压的 HarmonyOS
Command Line Tools 内置第三方 Python 文件纳入编码/路径静态扫描；1 项已有的
`report --language` 选项与语言注册表漂移；另 1 项同属该工具链文件扫描影响。OpenHarmony
专项测试和本阶段相关测试不受这些失败影响。

## 4. 真实模型复测

输入产物来自 `OH-22G-7B-reference-corpus-20260828/hiviewdfx_hiview`，源码仓库为
`openharmony_reference/openharmony_source_code/hiviewdfx_hiview`。只提交一个入口
`native:390:7a04ebac8bc5`，该入口有 9 个候选目标。

结果：

- 状态：`complete`；1 次调用，0 次重试；响应严格 JSON 解析成功；
- 9 个决定全部为 `add_edge`，且 9/9 通过高置信度、候选集合、检索候选和调用点/目标/注册证据校验；
- overlay 投影：`accepted_input=9`、`projected_edges=9`、`rejected=0`；
- 证据行号：调用点、注册项、目标函数共 27 条，`exact=27`，无未定位或歧义；
- token：输入 13,309、输出 2,522；费用约 `¥0.023094`；耗时约 10.94 秒。

源码逐项对照 `faultlog_formatter.cpp:378-387`：

| 枚举 | 注册处理函数 | 结果 |
| --- | --- | --- |
| `CPP_CRASH` | `GetCppCrashSectionLogs` | 一致 |
| `JS_CRASH` | `GetJsCrashSectionLogs` | 一致 |
| `CJ_ERROR` | `GetCjCrashSectionLogs` | 一致 |
| `APP_FREEZE` | `GetAppFreezeSectionLogs` | 一致 |
| `SYS_FREEZE` | `GetSysFreezeSectionLogs` | 一致 |
| `SYS_WARNING` | `GetSysWarningSectionLogs` | 一致 |
| `APPFREEZE_WARNING` | `GetAppFreezeWarningSectionLogs` | 一致 |
| `RUST_PANIC` | `GetRustPanicSectionLogs` | 一致 |
| `ADDR_SANITIZER` | `GetAddrSanitizerSectionLogs` | 一致 |

## 5. 第二个真实仓库复测

为检查协议修复的跨仓库泛化性，使用相同配置和参数复测
`communication_netmanager_base` 的 `NetConnCallbackStub::OnRemoteRequest` 入口
（`native:55:ead93abaf48a`），该入口有 6 个候选回调处理函数。

- 结果：1 次调用、0 次重试、合法 JSON；6/6 条决定为 `add_edge`，全部通过高置信度、候选集合、
  检索候选和源码证据校验；
- overlay：`accepted_input=6`、`projected_edges=6`、`rejected=0`；
- 证据行号：注册项和目标函数共 12 条为 `exact`；6 条调用点文本因模型报告行与源码实际行相差
  一行，经唯一邻近匹配校正（`nearby_unique`），没有歧义；
- token：输入 11,572、输出 1,728；费用约 `¥0.017815`；耗时约 12.28 秒；
- 源码对照 `net_conn_callback_stub.cpp:22-36` 的构造函数注册表，6 个目标分别为
  `OnNetAvailable`、`OnNetCapabilitiesChange`、`OnNetConnectionPropertiesChange`、
  `OnNetLost`、`OnNetUnavailable`、`OnNetBlockStatusChange`，与模型结果完全一致。

## 6. 产物

- `debug_outputs/OH-22G-10B-real-hiview-source-correct-20260828/llm_call_graph_recovery.json`
- `debug_outputs/OH-22G-10B-real-hiview-source-correct-20260828/llm_call_graph_overlay.json`
- `debug_outputs/OH-22G-10B-real-hiview-source-correct-20260828/prompt_preview.json`
- `debug_outputs/OH-22G-10B-real-hiview-source-correct-20260828/usage.json`
- `debug_outputs/OH-22G-10B-real-hiview-source-correct-20260828/run_metadata.json`
- `debug_outputs/OH-22G-10B-real-netmanager-source-correct-20260828/llm_call_graph_recovery.json`
- `debug_outputs/OH-22G-10B-real-netmanager-source-correct-20260828/llm_call_graph_overlay.json`
- `debug_outputs/OH-22G-10B-real-netmanager-source-correct-20260828/prompt_preview.json`
- `debug_outputs/OH-22G-10B-real-netmanager-source-correct-20260828/usage.json`
- `debug_outputs/OH-22G-10B-real-netmanager-source-correct-20260828/run_metadata.json`

另有一次仅用于确认测试路径的 `source-unavailable` 记录，保留在
`debug_outputs/OH-22G-10B-real-hiview-20260828/`，不作为模型效果结论。

## 7. 结论与边界

本阶段证明修复后的协议能够在真实 OpenHarmony 注册表场景下稳定解析并投影正确边，且失败重试
具有针对性诊断。一次成功不等于所有仓库、所有模型响应都没有格式问题；后续批量实验仍应检查
`response_diagnostics`，并继续以源码证据和严格投影作为最终门槛。
