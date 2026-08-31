# OH-22E-3：OpenHarmony 参考仓库批量评估记录

日期：2026-08-27  
项目：`/Users/shiyu/学习/hyl/new/OpenAnt`  
评估数据集：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code`  
仓库数量：9

## 1. 评估范围和运行方式

本轮针对用户指定的 `openharmony_reference/openharmony_source_code` 执行，
没有使用项目内的 `source_code_base`，也没有修改任何参考仓库源码。

所有仓库使用同一命令模板：

```bash
./.venv/bin/python libs/openant-core/parsers/c/test_pipeline.py <仓库路径> \\
  --output debug_outputs/OH-22E-3-reference-20260827/<仓库名> \\
  --processing-level reachable --platform openharmony --skip-tests
```

说明：

- `--platform openharmony` 启用 OpenHarmony 入口、IDL 和 native dispatch 逻辑；
- `--processing-level reachable` 同时验证原生 BFS、SemanticGraph overlay 和
  单调性；
- `--skip-tests` 排除测试/模糊测试目录，聚焦生产代码，减少仓库间统计偏差；
- 未加 `--llm`，因此本轮无大模型调用、无 API 费用；
- 未连接开发板，属于本地静态批量评估。

## 2. 总体结果

| 指标 | 合计 |
| --- | ---: |
| 扫描文件 | 4,973 |
| 提取函数 | 54,699 |
| 原生调用边 | 67,386 |
| SemanticGraph 边 | 1,835 |
| SemanticGraph 投影边 | 1,016 |
| 新增投影边 | 1,005 |
| 与原生图重合的投影边 | 11 |
| 残余间接调用点 | 136 |
| 候选边 | 769 |
| orphan | 87 |
| 结构化入口 | 355 |
| socket 接收调用 | 47 |
| socket 调用未覆盖/未标记 | 2 |
| native reachable | 1,933 |
| 增强后 reachable | 3,268 |
| reachable 单调性 | 9/9 `preserved` |
| 流水线成功 | 9/9 |
| 总耗时 | 约 564 秒 |

所有仓库的报告一致性检查均通过：原生边集合、投影边数量、已知函数端点、
候选目标、差集关系、reachable 单调性以及必需产物均没有发现结构性错误。

## 3. 分仓库统计

| 仓库 | 文件 | 函数 | 原生边 | 语义边 | 投影/新增/重合 | 残余/候选/orphan | 入口 | native reachable → enhanced | 单调性 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| communication_netmanager_base | 730 | 7,587 | 6,394 | 642 | 586 / 586 / 0 | 19 / 306 / 0 | 79 | 300 → 1,317 | preserved |
| developtools_hdc | 196 | 2,077 | 2,831 | 0 | 0 / 0 / 0 | 0 / 0 / 0 | 19 | 164 → 164 | preserved |
| hiviewdfx_faultloggerd | 359 | 3,020 | 3,415 | 22 | 22 / 22 / 0 | 3 / 22 / 0 | 21 | 79 → 79 | preserved |
| hiviewdfx_hilog | 117 | 864 | 851 | 2 | 2 / 0 / 2 | 1 / 2 / 1 | 22 | 79 → 79 | preserved |
| hiviewdfx_hiview | 1,054 | 7,059 | 5,687 | 56 | 26 / 18 / 8 | 22 / 26 / 48 | 68 | 202 → 202 | preserved |
| multimedia_audio_framework | 1,514 | 23,246 | 33,816 | 763 | 60 / 60 / 0 | 63 / 93 / 21 | 30 | 287 → 287 | preserved |
| startup_appspawn | 120 | 1,205 | 2,267 | 0 | 0 / 0 / 0 | 1 / 0 / 0 | 18 | 81 → 81 | preserved |
| startup_init | 343 | 2,728 | 4,929 | 9 | 0 / 0 / 0 | 0 / 0 / 0 | 48 | 628 → 628 | preserved |
| telephony_core_service | 540 | 6,913 | 7,196 | 341 | 320 / 319 / 1 | 27 / 320 / 17 | 50 | 113 → 431 | preserved |

“投影/新增/重合”分别表示 `projected_edge_count`、`new_edge_count` 和
`retained_edge_count`；它们不是漏洞数量，也不是运行时真实路径数量，而是
确定性语义边投影到函数调用图后的审计统计。

## 4. 入口和 socket 抽查

入口平台类别来自现有 OpenHarmony 入口检测器，socket 抽查则对扫描器实际选中
的生产源文件进行去注释/去字符串后的 `accept`、`recv`、`recvfrom`、
`recvmsg`、`recvmmsg` 词法扫描，再与函数索引和入口标记交叉比对。

| 仓库 | Binder 入口 | SA 生命周期 | native socket 入口 | socket 调用总数 | 未覆盖 |
| --- | ---: | ---: | ---: | ---: | ---: |
| communication_netmanager_base | 17 | 20 | 18 | 25 | 2 |
| developtools_hdc | 0 | 0 | 4 | 4 | 0 |
| hiviewdfx_faultloggerd | 1 | 0 | 4 | 4 | 0 |
| hiviewdfx_hilog | 0 | 0 | 4 | 4 | 0 |
| hiviewdfx_hiview | 2 | 5 | 1 | 1 | 0 |
| multimedia_audio_framework | 2 | 15 | 1 | 1 | 0 |
| startup_appspawn | 0 | 0 | 1 | 1 | 0 |
| startup_init | 0 | 5 | 7 | 7 | 0 |
| telephony_core_service | 7 | 14 | 0 | 0 | 0 |

发现的 2 个未覆盖调用均在
`communication_netmanager_base` 的头文件内联类方法中：

1. `utils/common_utils/include/epoller.h:242` 的
   `EpollServer::RunForEvents`；
2. `utils/common_utils/include/fwmark_epoller.h:150` 的
   `FwmarkEpollServer::RunForReceivers`。

两处源码确实包含 `accept(...)`，但当前函数提取结果只生成了外层类/方法的
不完整记录，没有覆盖这两个内联方法的行区间。因此这是“函数提取/范围建模”
层面的已确认遗漏，不是 socket 入口正则漏匹配。

其余 45 个 socket 调用均落在已提取并标记的函数中。`unknown_socket` 只表示
源码上下文没有足够的地址族信息，不能直接解读为互联网 socket；检测器仍将其
作为外部数据入口保留，避免漏掉后续风险分析。

## 5. 调用图恢复结果解读

### 5.1 覆盖较好的仓库

- `hiviewdfx_faultloggerd`：22 条 native dispatch 投影边全部新增，3 个残余；
- `telephony_core_service`：320 条投影边、319 条新增边，覆盖大量 callback/
  stub 分派；仍有 27 个残余和 17 个 lambda orphan；
- `communication_netmanager_base`：586 条投影边，覆盖 handler 和 service 两类
  关系，但存在 17 个“多个 service 实现”的语义 orphan，不能把这些边当作
  唯一运行时路径；
- `hiviewdfx_hilog`：2 条投影边均已存在于原生图，说明该仓库的相关分派并未
  带来新的可达函数。

### 5.2 仍需进一步分析的仓库

- `multimedia_audio_framework`：763 条语义边中只有 60 条能投影到已知函数，
  63 个残余、53 个无候选；另有 701 条 IDL 交易关系尚未与 native proxy/stub
  对齐。这更像是生成代码/IDL 实现映射不足，不能解释成“没有风险”；
- `hiviewdfx_hiview`：48 个 lambda orphan、22 个残余调用点，其中 15 个没有
  候选，适合作为后续 LLM 边审核样本；
- `startup_init`：9 条 IDL 接口交易边没有投影到函数，且 semantic graph
  记录了对应的 proxy/stub orphan；当前没有伪造函数边，但 IPC 覆盖明显不完整；
- `startup_appspawn`：存在 1 个无候选的函数指针调用；
- `developtools_hdc`：本轮没有间接调用残余和语义图边，静态调用图相对完整，
  但这不等价于所有动态回调都已证明。

## 6. 产物位置

批量根目录：

[OH-22E-3-reference-20260827](/Users/shiyu/学习/hyl/new/OpenAnt/debug_outputs/OH-22E-3-reference-20260827)

汇总文件：

- [batch_summary.csv](/Users/shiyu/学习/hyl/new/OpenAnt/debug_outputs/OH-22E-3-reference-20260827/batch_summary.csv)
- [batch_summary.json](/Users/shiyu/学习/hyl/new/OpenAnt/debug_outputs/OH-22E-3-reference-20260827/batch_summary.json)
- [batch_quality_analysis.json](/Users/shiyu/学习/hyl/new/OpenAnt/debug_outputs/OH-22E-3-reference-20260827/batch_quality_analysis.json)

每个仓库目录都包含：

```text
scan_results.json
analyzer_output.json
call_graph.json
call_graph_residuals.json
semantic_graph.json（无语义图时按实际情况缺失）
dispatch_recovery_diff.json
dataset.json
pipeline_results.json
run.log
```

## 7. 结论和后续建议

本轮确认：

1. 9 个参考仓库均能成功运行 OpenHarmony parser/reachability 流程；
2. 所有仓库的语义恢复都是加法式的，没有发现原生 reachable 被裁剪；
3. 差异报告与原生图、候选索引、实际输出之间保持一致；
4. 当前最明确的静态遗漏是两个头文件内联 `accept` 方法未进入函数范围；
5. 大型仓库的主要问题不是流水线崩溃，而是 IDL/generated proxy 映射和
   lambda/member-function-pointer 数据流仍有大量残余。

建议后续按以下顺序推进：

1. 先修复头文件内联方法的函数范围提取，重新验证 socket 入口覆盖；
2. 选 `multimedia_audio_framework`、`hiviewdfx_hiview`、
   `telephony_core_service` 的残余做 OH-22F LLM 边审核；
3. 对 `startup_init` 和 audio 的 IDL orphan 单独核查生成代码路径；
4. 继续保留“候选/残余/单调性”报告，不将投影边直接宣称为唯一运行时调用。
