# OH-22G-8：`hiviewdfx_faultloggerd` 真实模型调用图恢复

## 目的

在不重新执行完整漏洞扫描、不改写原生调用图的前提下，使用项目当前
`llm_reach` 配置，对一个小型 OpenHarmony 参考仓库进行一次真实模型恢复，
并用仓库源码逐条复核模型决定。此次实验同时验证一次性审核和入口驱动逐轮
调度器的边界行为。

## 输入与配置

- 源码仓库：`openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd`
- 静态产物：`debug_outputs/OH-22G-7B-reference-corpus-20260828/hiviewdfx_faultloggerd`
- 输入残余：3 个未解析调用点，候选目标总数 31（9 + 18 + 4）
- 入口：18 个结构化入口
- 配置来源：项目内 `config/openant/config.json`
- 配置名：`openharmony-live-gpt`
- provider：`autodl-openai`（OpenAI-compatible）
- 模型：`gpt-5.6-luna`
- 计价：输入 ¥0.812/M token，输出 ¥4.872/M token
- 受控参数：`max_shortlist=12`、`max_code_bytes=1200`、`max_tokens=6000`、
  `max_retries=1`；候选残余纳入审核；原始 `call_graph.json` 只读。

实验使用的执行逻辑等价于：在 `PYTHONPATH=libs/openant-core`、
`OPENANT_PROJECT_ROOT=/Users/shiyu/学习/hyl/new/OpenAnt` 环境下加载输入 JSON，
调用 `run_recovery_review`，再调用 `project_recovery_overlay`；随后调用
`run_iterative_recovery_review`（最多 4 轮、每轮最多 10 个点、最多 4 次模型请求）。

## 实际运行结果

### 一次性审核

- 状态：`complete`
- 首次响应不是 JSON 对象，触发 1 次重试；没有接受未通过严格解析的首轮内容
- 请求次数：2（初次 + 1 次重试）
- 输入 token：28,958
- 输出 token：3,191
- 总 token：32,149
- 费用：¥0.039060（USD 计价字段为 0，因为该模型配置为 CNY）
- 解析决定：6 条
- 接受：4 条
- 保留未解析：2 条
- 被验证器拒绝：0 条
- 投影 overlay 边：4 条

接受的 4 条边全部来自：

`services/snapshot/kernel_snapshot_parser.cpp:KernelSnapshotParser::ProcessSnapshotSection`
→ `ParseTransStart`、`ParseThreadInfo`、`ParseStackBacktrace`、`ParseProcessRealName`。

### 入口驱动逐轮审核

- 状态：`complete`
- 轮数：1
- 入口可达残余：0
- 调度/复核点：0/0
- 模型请求：0
- 投影边：0
- 未复核残余：3
- 终止原因：`frontier_exhausted`
- 费用：¥0

这不是异常：调度器只沿现有原生边和确定性语义边从入口扩展，当前 3 个残余
均不在该入口可达子图内，因此不会为无关代码付费。

## 源码核验

对照真实源码后，3 个残余点的可验证目标如下：

| 调用点 | 源码中实际注册/初始化的目标 | 模型本次接受 |
| --- | ---: | ---: |
| `MinidumpStreamFactory::CreateStream`（`minidump_factory.cpp:39`） | 9 | 0 |
| `ExidxEntryParser::Decode`（`exidx_entry_parser.cpp:407`） | 18 | 0 |
| `KernelSnapshotParser::ProcessSnapshotSection`（`kernel_snapshot_parser.cpp:218`） | 4 | 4 |

源码证据位置：

- `kernel_snapshot_parser.cpp:197-205` 的 `InitializeParseTable` 明确列出 4 个解析函数；
- `minidump_factory.cpp:50-60` 的 `RegisterDefaultCreator` 明确注册 9 个 `Instance` 函数；
- `exidx_entry_parser.cpp:343-361` 的局部 `decodeTable` 明确列出 18 个成员解码函数。

4 条被接受边的端点均存在于函数索引，模型提交的调用点/注册/目标证据均能在
对应源码行范围内匹配；未发现幽灵函数、错误文件或错误行号。按源码注册表计算，
本次候选边召回率为 `4/31 = 12.9%`，接受边的源码核验精确率为 `4/4 = 100%`。

## 结论与限制

1. 严格 JSON 解析、重试、候选集合约束、源码证据校验和独立 overlay 投影均正常工作。
2. 入口驱动早停有效：不可达残余不会被模型盲目审核，节省调用费用。
3. 本次低召回的主要原因不是 tree-sitter 没有看到调用点，而是请求上下文只包含
   残余调用者和候选函数，没有自动带上跨函数的注册表初始化。模型因此对
   `creators_` 和参数传入的 `decodeTable` 采取了正确但保守的 `keep_unresolved`。
4. 不能据此宣称 LLM 已完整恢复 OpenHarmony 间接边；下一轮应先改进“注册定义/调用
   链/局部初始化”的上下文检索，再用相同仓库和相同预算复测召回率。

## 产物

- `debug_outputs/OH-22G-8-real-faultloggerd-20260828/run_metadata.json`
- `debug_outputs/OH-22G-8-real-faultloggerd-20260828/llm_call_graph_recovery_one_shot.json`
- `debug_outputs/OH-22G-8-real-faultloggerd-20260828/llm_call_graph_overlay_one_shot.json`
- `debug_outputs/OH-22G-8-real-faultloggerd-20260828/llm_call_graph_recovery_iterative.json`
- `debug_outputs/OH-22G-8-real-faultloggerd-20260828/llm_call_graph_overlay_iterative.json`
- `debug_outputs/OH-22G-8-real-faultloggerd-20260828/one_shot_usage.json`
- `debug_outputs/OH-22G-8-real-faultloggerd-20260828/iterative_usage.json`

## 收尾验证

- 产物结构验证：`ARTIFACT_VALIDATION_OK`，7 个 JSON 文件均存在；输入
  `call_graph.json` 的 SHA-256 与运行元数据一致；4 条 overlay 边的 caller/target
  均存在于函数索引。
- 回归命令：
  ` .venv/bin/python -m pytest -q libs/openant-core/tests/openharmony/test_llm_call_graph_recovery.py libs/openant-core/tests/openharmony/test_llm_call_graph_projection.py libs/openant-core/tests/openharmony/test_llm_call_graph_rounds.py libs/openant-core/tests/test_scanner_llm_recovery_integration.py`
- 回归结果：`33 passed in 0.61s`。
