# OH-22G-9B：注册上下文接入 worklist/prompt

## 本切片范围

本切片把 OH-22G-9A 的只读 `registration_context` 接入恢复器的 worklist 和
模型 prompt，但没有重新调用真实模型。原生 `call_graph.json`、验证器和投影器
逻辑均未改变。

## 逻辑变化

旧逻辑：`run_recovery_review()` 只把残余调用者、候选目标函数和基础符号放入 prompt。

新逻辑：

- `build_recovery_worklist()` 增加显式 `include_registration_context` 开关；
- `run_recovery_review()` 和 `run_iterative_recovery_review()` 默认开启该开关，
  从残余诊断的 `repository` 字段读取仓库根目录；
- 每个 worklist 条目增加 `registration_context`，包含状态、相对文件、行号、源码片段、
  匹配原因和截断标记；
- prompt 明确要求模型把注册片段作为证据，文件路径/函数名本身不能作为注册证据，
  没有注册上下文时应保持 `keep_unresolved`；
- 直接调用 `build_recovery_worklist()` 仍默认关闭上下文，保留离线工具的兼容性。

默认每个残余点最多收集 6,000 字符，文件数量和单文件大小仍受收集器限制；没有
仓库路径时安全返回 `source_unavailable`，不会触发文件读取异常或自动补边。

## 离线真实仓库验证

输入批次：

`debug_outputs/OH-22G-7B-reference-corpus-20260828/hiviewdfx_faultloggerd`

结果：3 个残余点均进入 prompt，`registration_context.status=found`；

- `MinidumpStreamFactory::CreateStream`：包含 `RegisterCreator`、
  `RegisterDefaultCreator`，并将生产头文件 `minidump_factory.h` 排在测试噪声之前；
- `ExidxEntryParser::Decode`：包含局部 `decodeTable` 定义和调用点；
- `KernelSnapshotParser::ProcessSnapshotSection`：包含 `InitializeParseTable` 和
  `parseTable_ =` 初始化。

本次 prompt 检查：

- worklist：3 个 site；
- 每个上下文上限：6,000 字符；
- prompt 总长度：90,071 字符（约 87.96 KiB）；
- `InitializeParseTable`、`RegisterDefaultCreator`、`decodeTable` 和
  `RegisterCreator(` 均存在于 prompt；
- 未发起任何 API 请求。

## 测试

新增/修改测试覆盖：

1. worklist 可附加注册上下文；
2. 直接 worklist 调用默认保持 opt-in 兼容；
3. runner 将上下文传入 completion；
4. 同文件和跨文件注册检索；
5. 仓库不存在时安全降级。

回归命令覆盖恢复器、投影器、逐轮调度器、runner、上下文收集器和 scanner 集成。

结果：`42 passed in 0.67s`；Ruff 检查通过。

## 限制与下一步

- 本切片尚未验证“加入上下文后模型召回率是否提升”；需要另一个受控真实 API 切片；
- 当前每个 site 独立扫描文件，多个残余点可能重复读取同一仓库，后续可增加仓库级缓存；
- 6,000 字符预算下仍可能截断大量候选函数片段，下一步应优先保留注册写入和初始化链，
  再压缩重复的目标函数实现。

