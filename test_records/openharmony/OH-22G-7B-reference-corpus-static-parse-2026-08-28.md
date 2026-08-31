# OH-22G-7B：OpenHarmony 参考仓库静态解析批次

日期：2026-08-28  
源码目录：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code`  
输出目录：`debug_outputs/OH-22G-7B-reference-corpus-20260828`

## 执行范围

本阶段只运行 OpenAnt 的 OpenHarmony C/C++ parser 和静态 reachable 过滤：

- `language=c`（tree-sitter C/C++ 解析器）；
- `platform=openharmony`；
- `processing_level=reachable`；
- 默认跳过测试目录；
- 不启用 LLM、漏洞分析、验证、动态测试或报告生成；
- 每个仓库输出到新的独立目录，不覆盖旧批次。

## 批次结果

| 仓库 | C/C++ 文件 | 函数索引 | 原生边 | 入口数 | reachable 单元 | 残余 site | 候选边 | 语义图 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `communication_netmanager_base` | 730 | 6,967 | 5,448 | 72 | 718 | 17 | 306 | 有 |
| `developtools_hdc` | 196 | 2,031 | 2,826 | 18 | 163 | 0 | 0 | 无（0 条语义边） |
| `hiviewdfx_faultloggerd` | 359 | 2,810 | 2,559 | 18 | 59 | 3 | 31 | 有 |
| `hiviewdfx_hilog` | 117 | 796 | 777 | 17 | 72 | 0 | 0 | 有 |
| `hiviewdfx_hiview` | 1,054 | 5,531 | 3,998 | 50 | 162 | 1 | 9 | 有 |
| `multimedia_audio_framework` | 1,514 | 22,032 | 28,324 | 28 | 273 | 55 | 66 | 有 |
| `startup_appspawn` | 120 | 1,195 | 2,263 | 18 | 81 | 1 | 0 | 无（0 条语义边） |
| `startup_init` | 343 | 2,704 | 4,922 | 47 | 626 | 0 | 0 | 有 |
| `telephony_core_service` | 540 | 6,238 | 6,063 | 44 | 356 | 4 | 0 | 有 |
| **合计** | **4,973** | **50,304** | **57,180** | **312** | **2,510** | **81** | **412** | **7/9 有文件** |

9/9 仓库静态解析成功。最大仓库 `multimedia_audio_framework` 用时约 317 秒，其余仓库均在约 1–68 秒内完成。

## 产物完整性

每个仓库均生成：

- `call_graph.json`
- `call_graph_residuals.json`
- `dataset.json`
- `pipeline_results.json`
- `scan_results.json`

7 个仓库另外生成 `semantic_graph.json`。`developtools_hdc` 和 `startup_appspawn` 的确定性 OpenHarmony 语义边数为 0，parser 没有写入空语义图文件；这记录为语义图覆盖缺口，不是解析失败。

所有 81 个残余调用点的源码文件均存在于对应参考仓库；caller ID 和候选 target ID 均能在函数索引中找到，没有发现悬空索引。

## 结论

静态解析阶段通过，可作为后续 OH-22G-6 逐轮恢复的输入。该阶段证明了解析器能够处理这 9 个仓库，但不等价于证明调用图完整，也不包含 LLM 漏边恢复或漏洞分析结论。

测试结果：通过（9/9 parser 成功；语义图无文件的两个仓库已明确记录）。
