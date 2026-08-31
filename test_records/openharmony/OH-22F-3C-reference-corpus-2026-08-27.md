# OH-22F-3C：OpenHarmony 参考仓库批量评估记录

## 1. 测试目的

验证 OH-22F-3C“OpenHarmony 数字 dispatch code 证据解析器”在参考仓库上的实际表现，区分以下三件事：

1. 调用图残余中是否已经提取出候选处理函数；
2. 解析器是否能从源码中为 selector 找到可审计的整数值和定义证据；
3. 哪些结果是当前实现的真实能力，哪些是表达式类型或输入范围造成的已知缺口。

本次只做离线源码分析，不调用大模型、不连接设备、不修改调用图、reachable 或 dataset，也没有重新执行完整扫描。

## 2. 测试范围与输入

- 源码根目录：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code`
- 本目录实际包含 9 个仓库：`communication_netmanager_base`、`developtools_hdc`、`hiviewdfx_faultloggerd`、`hiviewdfx_hilog`、`hiviewdfx_hiview`、`multimedia_audio_framework`、`startup_appspawn`、`startup_init`、`telephony_core_service`。
- 调用图残余输入：`debug_outputs/OH-22E-3-reference-20260827/<仓库>/call_graph_residuals.json`
- 选择同一批 OH-22E-3 输入，是为了避免把不同实验批次的 parser/LLM 结果混在一起。
- 每个仓库的完整证据输出：`debug_outputs/OH-22F-3C-reference-corpus-20260827/<仓库>/openharmony_dispatch_code_evidence.json`
- 批量汇总：`debug_outputs/OH-22F-3C-reference-corpus-20260827/batch_summary.json`

执行的核心命令为：

```bash
PYTHONPATH=libs/openant-core .venv/bin/python - <<'PY'
from pathlib import Path
import json
from core.platforms.openharmony.dispatch_code_evidence import build_dispatch_code_evidence

for repo in sorted(Path("../openharmony_reference/openharmony_source_code").iterdir()):
    residual = Path("debug_outputs/OH-22E-3-reference-20260827") / repo.name / "call_graph_residuals.json"
    diagnostics = json.loads(residual.read_text())
    result = build_dispatch_code_evidence(diagnostics, repository=repo)
    print(repo.name, result["summary"])
PY
```

## 3. 批量结果

| 仓库 | 证据站点 | 候选 case | 已解析整数值 | 未解析 | 冲突 | 源码文件 | 当前解析率 |
|---|---:|---:|---:|---:|---:|---:|---:|
| communication_netmanager_base | 19 | 307 | 0 | 307 | 0 | 1085 | 0.0% |
| developtools_hdc | 0 | 0 | 0 | 0 | 0 | 289 | 不适用 |
| hiviewdfx_faultloggerd | 3 | 22 | 4 | 18 | 0 | 504 | 18.2% |
| hiviewdfx_hilog | 1 | 6 | 0 | 6 | 0 | 134 | 0.0% |
| hiviewdfx_hiview | 22 | 32 | 14 | 18 | 0 | 1424 | 43.8% |
| multimedia_audio_framework | 63 | 127 | 13 | 114 | 0 | 2650 | 10.2% |
| startup_appspawn | 1 | 0 | 0 | 0 | 0 | 297 | 不适用 |
| startup_init | 0 | 0 | 0 | 0 | 0 | 845 | 不适用 |
| telephony_core_service | 27 | 330 | 45 | 285 | 0 | 851 | 13.6% |
| **合计** | **136** | **824** | **76** | **748** | **0** | **8079** | **9.2%** |

这里的“源码文件”是本阶段实际读取的 C/C++ 源文件和头文件数量；`status=complete` 只表示文件读取完成，不表示所有 selector 都已经得到值。

## 4. 结果解读

### 4.1 候选处理函数提取情况

本次输入中，候选 handler 不是空的仓库有 6 个：`communication_netmanager_base`、`hiviewdfx_faultloggerd`、`hiviewdfx_hilog`、`hiviewdfx_hiview`、`multimedia_audio_framework`、`telephony_core_service`。这说明前一阶段的调用图残余能够发现多个真实的函数指针/映射分派点。

`developtools_hdc`、`startup_init` 没有残余 dispatch site；`startup_appspawn` 有 1 个间接调用站点，但没有候选 handler。它们不能据此判定“没有入口”，只能说明当前调用图残余输入没有提供可供本阶段解析的候选集合。

### 4.2 当前结果明显低估的原因

在 `communication_netmanager_base` 中，307 个 selector 几乎全部是如下形式：

```cpp
static_cast<uint32_t>(ConnCallbackInterfaceCode::NET_AVAILABLE)
```

源码中确实存在 `ConnCallbackInterfaceCode` 枚举定义，且批量分析的定义索引发现其中 299 个未解析项对应的符号能够在源码中找到。当前实现虽然有整数表达式求值函数，但构建 case 时仍先把整个 cast 字符串当作“符号名”查找，没有把这个顶层表达式交给求值器，因此全部落入 `unresolved_symbol`。这属于实现路径缺口，不是源码中不存在值。

在 `hiviewdfx_faultloggerd` 中，18 个未解析项是 `0xc0`、`0xf0` 等数值字面量；值本身已经写在 selector 里，只是当前实现只查定义表，没有直接把数字字面量标为 resolved。

在 `telephony_core_service` 中，大量 selector 是 `uint32_t(Enum::VALUE)` 形式或具名 enum 成员，分别暴露出 C++ 函数式 cast、具名 enum 解析和命名空间/类型别名处理不足的问题。

### 4.3 不应按“整数解析率”评价的结果

- `hiviewdfx_hilog` 的 6 个候选是字符串 selector，如 `"time"`、`"epoch"`、`"msec"`、`"usec"`，属于字符串命令分派，不是整数 transaction code。
- `multimedia_audio_framework` 的 66 个未解析项是 `u"-h"`、`u"-d"` 等字符串命令；另有 48 个 `UPDATE_STATUS` 等消息枚举/符号，需支持具名枚举和消息分派语义后再判断。
- 一些 lambda/callback site 没有候选列表，它们是回调注册或数据驱动的间接调用，不能通过本阶段的 selector 数值解析补齐。

因此，9.2% 是“当前整数证据实现直接产出的解析率”，不是调用图候选覆盖率，也不是漏洞分析准确率。

## 5. 源码抽查结论

对代表性仓库做了源码交叉检查：

1. `communication_netmanager_base` 的 `conn_ipc_interface_code.h` 明确定义了 `ConnCallbackInterfaceCode` 及其枚举成员；当前 0/307 是表达式入口未接入求值器导致的假阴性式统计。
2. `hiviewdfx_faultloggerd` 的 `exidx_entry_parser.cpp` 直接使用 `0xc0`、`0xf0`、`0xc8` 等编码；当前 4/22 已解析，但其余数字字面量不应继续报告成未知符号。
3. `hiviewdfx_hiview` 的 `faultlog_info_inner.h` 定义了具名 `enum FaultLogType`；当前正则未覆盖普通具名 enum 的声明形式，所以 `FaultLogType::ADDR_SANITIZER` 等 18 项未解析。
4. `multimedia_audio_framework` 的 `hpae_msg_channel.h` 定义了 `enum HpaeMsgCode`，同时仓库中还存在 `u"-h"` 形式的文本命令分派，二者需要分别处理，不能用同一整数规则硬套。

## 6. 测试校验

批量产物校验通过：

```text
9/9 个仓库证据 JSON 可读取
9/9 个仓库 status=complete
summary 断言通过：candidate_cases=824，resolved_cases=76
SUMMARY_ASSERTIONS_OK
```

本阶段没有修改源码，因此没有新增单元测试；OH-22F-3C 实现本身的既有测试结果为 `147 passed, 2 skipped`，Ruff 检查通过。

## 7. 结论与后续建议

当前实现已经能在所有 9 个参考仓库上稳定完成源码遍历、注册证据保留和部分简单整数定义解析，且没有发现冲突值；但真实 OpenHarmony 代码中的 cast、具名 enum、数值字面量和字符串命令使直接解析率只有 9.2%。

下一步应先修正顶层 selector 表达式求值入口，并补充普通具名 enum、底层类型 enum、C++ 函数式 cast 和数字字面量的测试；字符串命令与回调注册则应分别建立非整数 dispatch evidence 类型。修复前不应把当前批量结果宣称为完整的 transaction-code 覆盖。

