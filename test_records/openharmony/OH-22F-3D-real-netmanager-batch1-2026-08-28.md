# OH-22F-3D：真实模型分派复核试验记录

日期：2026-08-28  
仓库：`communication_netmanager_base`  
阶段：OH-22F-3D（LLM 分派证据复核协议的小规模真实试验）

## 1. 原项目逻辑与本次试验逻辑

原项目的确定性 OpenHarmony 分派解析器可以识别注册语句和候选 handler，但遇到
`static_cast<uint32_t>(Enum::VALUE)` 这类符号表达式时，为避免猜测，会把 selector
标记为 `unresolved_symbol`，因此不会把数值写回原始调用图。

本次试验在原始证据之外建立独立的 LLM 复核链路：

1. 从已有 evidence 中取第一个受控批次的未解析 case；
2. 给模型提供调用点、注册语句、调用者/目标函数（如有）和源码中的 enum 定义；
3. 模型只能解释已有 case 的 selector/value，不能创建新的 handler、调用边或文件路径；
4. 结果必须是严格 JSON，并由本地校验器检查 case ID、证据是否来自上下文、值类型和置信度；
5. 不修改 `call_graph.json`、原始 evidence 或 scanner 主流程。

## 2. 输入与运行配置

- 源码仓库：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/communication_netmanager_base`
- 分派证据：`debug_outputs/OH-22F-3C-reference-corpus-20260827/communication_netmanager_base/openharmony_dispatch_code_evidence.json`
- 函数索引/调用图：`debug_outputs/OH-22E-3-reference-20260827/communication_netmanager_base/call_graph.json`
- 项目配置：`config/openant/config.json`
- LLM 配置：`openharmony-live-gpt`
- Provider：`autodl-openai`（OpenAI 兼容接口）
- Model：`gpt-5.6-luna`
- 本次最大响应 token：4000
- 批次上下文上限：120,000 字符
- 成功批次：1
- 成功批次 case 数：6

首批大小会受到源码上下文实际长度影响；同一 worklist 的源码定义片段来自集合索引，
上下文顺序变化可能使 120,000 字符限制下的首批为 6 或 7 个。本次以实际发送的
6-case 批次为准，所有 6 个 case 均已复核。

## 3. 执行结果

结果文件：

- `debug_outputs/OH-22F-3D-real-netmanager-batch1-20260828/dispatch_llm_review.json`
- `debug_outputs/OH-22F-3D-real-netmanager-batch1-20260828/input_manifest.json`
- `debug_outputs/OH-22F-3D-real-netmanager-batch1-20260828/source_crosscheck.json`

协议执行摘要：

| 指标 | 结果 |
|---|---:|
| worklist case | 6 |
| LLM 批次 | 1 |
| API 调用 | 1 |
| 重试 | 0 |
| 解析出的决策 | 6 |
| 高置信度 accepted | 6 |
| advisory | 0 |
| rejected | 0 |
| keep_unresolved | 0 |
| 未复核 case | 0 |
| 输入 token | 32,673 |
| 输出 token | 1,502 |
| 成功请求成本 | ¥0.033848 |
| 耗时 | 32.042 秒 |

模型给出的值为：

| case | selector | 目标 handler | 模型值 | 置信度 |
|---|---|---|---:|---|
| `case:2a429fab227ba26b` | `ConnCallbackInterfaceCode::NET_AVAILABLE` | `OnNetAvailable` | 0 | high |
| `case:05588ada96ab68ab` | `ConnCallbackInterfaceCode::NET_CAPABILITIES_CHANGE` | `OnNetCapabilitiesChange` | 1 | high |
| `case:c5a2e57a1f3d209f` | `ConnCallbackInterfaceCode::NET_CONNECTION_PROPERTIES_CHANGE` | `OnNetConnectionPropertiesChange` | 2 | high |
| `case:bc340cbd1d5d5cd0` | `ConnCallbackInterfaceCode::NET_LOST` | `OnNetLost` | 3 | high |
| `case:6bea7b4f87da8d81` | `ConnCallbackInterfaceCode::NET_UNAVAILABLE` | `OnNetUnavailable` | 4 | high |
| `case:b6c83d7d049b34a6` | `ConnCallbackInterfaceCode::NET_BLOCK_STATUS_CHANGE` | `OnNetBlockStatusChange` | 5 | high |

## 4. 独立源码交叉核对

核对脚本没有使用模型的 reason 作为正确性依据，而是重新读取仓库源码：

- 注册文件：`frameworks/native/netconnclient/src/proxy/net_conn_callback_stub.cpp`
- enum 文件：`interfaces/innerkits/netconnclient/include/proxy/conn_ipc_interface_code.h`
- enum `ConnCallbackInterfaceCode` 为连续的隐式枚举成员，源码值为 0、1、2、3、4、5；
- 每个 selector 的注册语句都引用了对应目标成员函数；
- 每个目标方法名都能在注册源文件中找到；
- LLM 返回的 6 个值与独立解析出的源码值全部一致。

交叉核对统计：

| 检查项 | 通过数 |
|---|---:|
| 注册符号与目标同时存在 | 6/6 |
| 目标方法引用存在 | 6/6 |
| enum 值与模型值一致 | 6/6 |
| 总体通过 | 6/6 |

## 5. 成本与异常说明

第一次真实请求已经完成，但落盘脚本错误调用了不存在的 `TokenTracker.totals()`，
在写文件前退出，因此该次响应无法从本地恢复。随后修正为 `get_summary()` 并重新
请求同一批次；本目录保存的是第二次成功请求的完整结果。记录中的 ¥0.033848
只代表第二次成功请求，第一次请求如果被服务端计费，其金额不在本地 tracker 中，
无法可靠还原，实际账户总费用可能略高。

## 6. 结论与边界

本次真实试验表明：对于“注册语句 + 源码 enum 定义”这类未解析 selector，LLM 能在
受限上下文中返回正确数值，并且本地证据校验可以阻止上下文外的伪造证据。该结果
只验证了 1 个仓库、1 个批次、6 个连续隐式 enum case，不能据此宣称所有 OpenHarmony
分派形式都已覆盖。

当前仍保持安全边界：结果是独立 advisory artifact，没有自动合并到调用图；后续如
要接入 scanner，应先增加“接受 llm_verified 值是否参与 reachable/调用图”的独立
开关和回归测试。
