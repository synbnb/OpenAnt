# OH-22G-9C：注册上下文增强后的真实模型调用图恢复复测

日期：2026-08-28  
仓库：`openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd`  
模型：项目配置 `openharmony-live-gpt`（`autodl-openai / gpt-5.6-luna`）

## 1. 目的

比较 OH-22G-8 的旧 prompt 与 OH-22G-9B 接入 `registration_context` 后的真实模型效果。
两次实验使用同一份静态产物、同一源码仓库、同一模型和同一候选集合；本轮只增加跨函数注册表/初始化表上下文，不修改原始 `call_graph.json`。

## 2. 输入和运行参数

- 静态产物：`debug_outputs/OH-22G-7B-reference-corpus-20260828/hiviewdfx_faultloggerd`
- 源码：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd`
- 残余间接调用点：3 个
- 候选目标：31 个（源码中可直接核验的参考真值也是 31 个）
- `max_shortlist=12`、`max_code_bytes=1200`、`max_retries=1`、`max_tokens=6000`
- 注册上下文：开启；每个残余点最多 512 个文件、单文件 1,000,000 字节、上下文 6,000 字符
- 结果目录：`debug_outputs/OH-22G-9C-real-faultloggerd-20260828`

注册上下文收集器实际扫描了 355 个生产源码文件，3 个残余点均返回 `found`：

| 残余点 | 分发表 | 匹配文件 | 片段数 | 上下文 |
|---|---|---:|---:|---:|
| `minidump_factory.cpp:39` | `creators_` | 3 | 10 | 6,000 字符（有截断） |
| `exidx_entry_parser.cpp:407` | `decodeTable` | 1 | 30 | 6,000 字符（有截断） |
| `kernel_snapshot_parser.cpp:218` | `parseTable_` | 5 | 24 | 6,000 字符（有截断） |

## 3. 结果对比

| 指标 | OH-22G-8 旧 prompt | OH-22G-9C 注册上下文 prompt |
|---|---:|---:|
| API 调用 | 2（1 次格式重试） | 1（无重试） |
| 输入 token | 28,958 | 25,943 |
| 输出 token | 3,191 | 9,028 |
| 成本 | ¥0.039060 | ¥0.065050 |
| 模型接受边 | 4 | 31 |
| 源码真值召回率 | 4/31 = 12.9% | 31/31 = 100% |
| 接受边源码精确率 | 4/4 = 100% | 31/31 = 100% |
| 保留未解析 | 2 | 0 |
| 拒绝/错误 | 0/0 | 0/0 |

本轮生成的 `llm_call_graph_overlay.json` 包含 31 条唯一增强边和 34 个节点：

- 31 个目标 ID 全部属于输入候选集合；
- 34 个节点（3 个调用者和 31 个目标）全部存在于原始 `call_graph.json` 的函数索引；
- 无重复边、自环、幽灵节点或被投影器拒绝的边；
- 原始 `call_graph.json`、`call_graph_residuals.json` 和 `dataset.json` 未被修改。

## 4. 源码逐条核验

对照同一源码快照中的实际初始化语句，31 条边全部匹配：

1. `MinidumpStreamFactory::CreateStream` 的 `creators_` 间接调用对应
   `RegisterDefaultCreator` 中的 9 条 `RegisterCreator(..., X::Instance)` 注册；
2. `ExidxEntryParser::Decode` 的 `decodeTable[i].decoder` 间接调用对应表中的 18 个
   `&ExidxEntryParser::Decode...` 成员函数指针；
3. `KernelSnapshotParser::ProcessSnapshotSection` 的 `parseTable_` 间接调用对应
   `InitializeParseTable` 中的 4 条 `SnapshotSection → Parse...` 注册。

模型返回的注册文本和目标函数文本均可在源码中找到，目标函数签名和文件路径也与原函数索引一致。

## 5. 证据质量和限制

这次实验不能解释为所有仓库都能达到 100% 召回。需要特别注意：

- 三类注册证据的 `start_line` 在模型返回中普遍偏向表头或前一行（例如第一条
  `RegisterCreator` 文本报告为 51 行，而当前源码实际为 52 行）；这是模型依据未逐行编号的
  片段自行对齐造成的证据定位误差，不影响本轮目标集合和注册文本的真实性；
- 调用点和目标函数行号核验通过，但注册证据行号仍不应直接作为最终报告行号；后续应在
  prompt 中提供逐行编号片段，并增加确定性证据行号归一化；
- 上下文按 6,000 字符截断，且本轮候选正好覆盖三个结构化表，不能代表跨文件宏注册、动态
  加载、条件编译或复杂别名场景；
- 本轮只验证“恢复边是否存在”，没有重新执行漏洞检测或动态验证，也没有修改 reachable 的
  原始输入。

## 6. 结论

在 `hiviewdfx_faultloggerd` 这个受控样本上，加入跨函数注册/初始化上下文后，真实模型从旧 prompt 的
12.9% 召回提升到 100%，且没有出现误加边；成本增加到 ¥0.065050，仍低于本轮预算。该结果支持继续
保留注册上下文增强，但下一阶段应先修复证据行号对齐并在更多 OpenHarmony 仓库上做小批量复测，之后
再决定是否把该能力作为默认扫描路径。

