# OH-22C-2：OpenHarmony 残余调用点去重与机制分类测试记录

日期：2026-08-27  
范围：`libs/vulnfounder-core/core/platforms/openharmony/llm_call_graph_recovery.py` 及其单元测试  
数据集：`debug_outputs/OH-22B-2I-all-20260827/` 下 9 个 OpenHarmony 仓库的 `call_graph_residuals.json` 与 `dataset.json`

## 1. 本阶段目标

上一版工作列表按诊断记录逐条生成任务。同一个源码位置如果被多个命名空间包装单元或不同解析通道报告，会重复进入复核队列，既浪费上下文和 API 预算，也容易让用户误以为存在多个不同调用点。本阶段只做两件事：

1. 按源码位置合并重复残余，并保留所有调用者、候选目标和解析器证据。
2. 在进入 LLM 之前标注残余机制：本地表/队列分派、成员函数模板分派、外部回调、外部 HDI/RIL 接口、动态库符号，或真正未知的间接调用。

本阶段没有把任何推测目标写回 `call_graph.json`，也没有调用真实大模型。

## 2. 原逻辑与修改后逻辑

### 原逻辑

- 每条 `unresolved_call_sites` 或 `lambda_dispatch.call_sites` 直接生成一个 worklist 条目。
- `site_id` 把 `caller_id` 作为主要身份的一部分；同一文件、同一行、同一表达式只要 caller ID 不同，就会成为多个任务。
- 没有机制分类，调用点进入工作列表后只能依赖后续模型判断。

### 修改后逻辑

- 以 `(诊断通道 native/lambda, 文件, 行号, 表达式)` 作为源码位置键。
- 同一源码位置只保留一个条目，同时合并：
  - `caller_ids` 和 `duplicate_count`；
  - 所有 `candidate_target_ids`；
  - `symbols` 中的非空解析证据；
  - 更高优先级和安全相关标记。
- `site_id` 只依赖源码位置（文件、行号、表达式），不依赖解析器给出的 reason 或 dispatch table，因此不同解析通道的元数据不会改变身份。
- 新增 `classification`、`analysis_route`、`llm_eligible` 字段。分类只决定后续分析路线，不代表已经补全调用边：
  - `local_dispatch / deterministic`：表达式直接读取 `map/table/queue` 中的 callable，例如 `iter->second(...)`；
  - `external_interface / external_boundary`：表达式直接通过 HDI/RIL 接口调用；
  - `template_dispatch / deterministic`：通过类型化成员函数指针模板转发，例如 `object->*(_func)`；
  - `external_dynamic_symbol / external_boundary`：目标由 `dlopen/dlsym` 等动态符号取得；
  - `external_callback / external_boundary`：Taihe、JS、FFI 或 native callback 由仓库外部提供；
  - `unknown_indirect / llm_review`：没有上述信号，才允许后续 LLM 复核。
- `security_relevant_only=True` 时，外部边界只作为分类元数据保留，不送入“仓库内目标恢复”的 LLM 队列，避免模型虚构仓库内 target ID。

分类优先使用残余表达式和 `symbols` 的直接信号；只有直接信号不足时才检查 caller 的源码上下文，以避免 caller 单元中内联的邻近函数误触发分类。

## 3. 测试驱动过程

### RED

先加入以下两个测试：

- 同一源码位置、不同 caller ID 和不同解析元数据应合并，并保持稳定 `site_id`；
- 本地 map、成员模板、外部 callback、动态符号和外部 RIL 接口应进入不同路线。

实现尚未加入时，测试因 `classify_recovery_site` 尚不存在而失败：

```text
ImportError: cannot import name 'classify_recovery_site'
```

### GREEN

实现最小逻辑后运行：

```text
source .venv/bin/activate
pytest -q libs/vulnfounder-core/tests/openharmony/test_llm_call_graph_recovery.py
......                                                                   [100%]
6 passed in 0.03s
```

随后运行全部 OpenHarmony 专项测试：

```text
pytest -q libs/vulnfounder-core/tests/openharmony
118 passed, 2 skipped in 0.61s
```

静态检查：

```text
ruff check \
  libs/vulnfounder-core/core/platforms/openharmony/llm_call_graph_recovery.py \
  libs/vulnfounder-core/tests/openharmony/test_llm_call_graph_recovery.py
All checks passed!
```

## 4. 真实 OpenHarmony 残余回归

工作列表构建使用每个仓库 `dataset.json` 的函数单元作为索引，未调用模型。`raw` 是无候选原始记录数，`unique` 是合并后的源码位置数，`duplicates_removed` 是被合并掉的重复记录数，`security_queue` 是 `security_relevant_only=True` 后仍需仓库内复核的数量。

| 仓库 | raw | unique | duplicates_removed | security_queue | 分类结果 |
|---|---:|---:|---:|---:|---|
| communication_netmanager_base | 2 | 2 | 0 | 2 | local_dispatch 2 |
| developtools_hdc | 0 | 0 | 0 | 0 | 无残余 |
| hiviewdfx_faultloggerd | 1 | 1 | 0 | 1 | local_dispatch 1 |
| hiviewdfx_hilog | 0 | 0 | 0 | 0 | 无残余 |
| hiviewdfx_hiview | 19 | 12 | 7 | 4 | local_dispatch 12 |
| multimedia_audio_framework | 55 | 53 | 2 | 8 | external_callback 44；local_dispatch 5；template_dispatch 4 |
| startup_appspawn | 1 | 1 | 0 | 0 | external_dynamic_symbol 1 |
| startup_init | 0 | 0 | 0 | 0 | 无残余 |
| telephony_core_service | 11 | 4 | 7 | 3 | external_interface 1；template_dispatch 3 |
| **合计** | **89** | **73** | **16** | **18** | **unknown_indirect 0** |

本次基线中 73 个位置全部获得了本地或外部边界信号，因此 `llm_eligible` 为 0。这不表示 73 个调用边已经恢复，而是表示它们不应交给“凭空猜测仓库内目标”的 LLM 队列：本地/模板分派应进入后续确定性解析器，外部回调/接口/动态符号应建模为外部边界。

## 5. 源码抽查依据

- `communication_netmanager_base`：`services/netstatsmanager/src/net_stats_listener.cpp:73/89` 的 `callbackData->second(...)` 和 `callback->second(...)` 是本地 callable 表读取；对应注册逻辑位于 `services/netstatsmanager/src/net_stats_service.cpp`。
- `hiviewdfx_faultloggerd`：`tools/process_dump/minidump_parser/minidump_factory.cpp:39` 读取 `creators_`，工厂 creator 在同文件后续注册，属于本地 map 分派。
- `hiviewdfx_hiview`：EventRaw、memory collector、export strategy 和 faultlog formatter 的 `iter->second(...)` 均是本地 handler 表；头文件单元被多个命名空间包装，所以 19 条合并为 12 个源码位置。
- `multimedia_audio_framework`：44 条 `frameworks/taihe/...` 下的 `(*cacheCallback)(...)` 由 Taihe/JS 侧提供，仓库内没有可安全命名的 C++ 目标；音频 engine 的 handler map 和 `AudioSuite`/HPAE 模板转发则分别归为 local/template。
- `startup_appspawn`：`modules/common/appspawn_common.c:312` 的 `(*initParam)(processName)` 与 `dlopen/dlsym` 动态库符号加载相关，不能从仓库函数索引推造目标。
- `telephony_core_service`：`services/tel_ril/include/tel_ril_base.h:137` 的 `rilInterface->*(_func)` 直接跨 RIL 接口边界；`tel_ril_callback.h` 与 `tel_ril_manager.h` 的其余位置是内部模板转发。

## 6. 额外基线信息

尝试运行整个 Python 测试目录时，首个失败来自 conformance 测试依赖未安装的 Go 工具链，而非本阶段文件：

```text
libs/vulnfounder-core/tests/conformance/test_F1_receiver_type_contract.py::test_go
FileNotFoundError: [Errno 2] No such file or directory: 'go'
```

因此本阶段验收以 OpenHarmony 专项测试、目标模块单元测试、ruff 和真实仓库只读回归为准；全量测试的 Go 依赖问题需要单独补环境后再复测。

## 7. 当前边界与下一步

1. 本阶段仍是 advisory（建议）层：没有修改 `call_graph.json`、`SemanticGraph` 或可达性结果。
2. `local_dispatch` 和 `template_dispatch` 已确认应走确定性解析，但对应的注册表/参数传播解析器尚未在本阶段实现；它们仍会出现在残余报告中。
3. 外部 callback、HDI/RIL 和动态符号不能让 LLM 虚构仓库内 target，后续应以 external boundary 节点或可观察 ABI 信息表达。
4. 对没有任何信号的 `unknown_indirect`，后续才使用已有的严格 JSON LLM 协议，并限制在函数索引候选中选择目标。
5. 下一阶段建议先实现本地注册表和模板实参传播，将可确定的边投影到临时图并做边数/可达性对比；确认仍有未知位置后，再启用 LLM 复核。

