# OH-22G-9A：跨函数注册上下文收集器

## 本切片范围

本切片只新增源码上下文收集器，不接入 LLM prompt、不修改 scanner、不修改
`call_graph.json` 或 `semantic_graph.json`。目标是验证：给定一个残余调用点、
候选函数索引和仓库根目录，能否在有限预算内找回分发表初始化、注册函数和跨文件
构造函数信息。

实现文件：`libs/openant-core/core/platforms/openharmony/registration_context.py`

## 当前逻辑

- 调用者文件和候选目标文件优先扫描；
- 再在仓库内有限扫描 C/C++ 源文件；
- 根据分发表变量、候选函数限定名/所属类名和调用者所属类名定位源码行；
- 对命中行扩展少量上下文，合并相邻范围；
- 排除 `.git`、构建目录、第三方目录以及测试/示例目录，避免通用函数名污染上下文；
- 输出相对路径、起止行号、源码片段、匹配原因和截断标记；
- 仓库不存在、路径越界或没有命中时只返回 `source_unavailable`/`not_found`，不生成边。

## 测试结果

### 单元测试

命令：

```text
PYTHONPATH=libs/openant-core .venv/bin/python -m pytest -q \
  libs/openant-core/tests/openharmony/test_registration_context.py
```

结果：`3 passed`。

覆盖内容：

1. 同一文件的分发表调用与初始化表；
2. 注册函数和构造函数分布在不同文件；
3. 仓库不存在时安全降级。

### 真实仓库离线验证

输入：

`openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd`

3 个残余点均返回 `found`：

| 调用点 | 关键检索结果 | 片段数/匹配文件数 | 是否截断 |
| --- | --- | ---: | --- |
| `MinidumpStreamFactory::CreateStream` | `RegisterCreator`、`RegisterDefaultCreator`、生产头文件 | 53/11 | 是 |
| `ExidxEntryParser::Decode` | 局部 `decodeTable` 定义及调用 | 39/3 | 否 |
| `KernelSnapshotParser::ProcessSnapshotSection` | `InitializeParseTable`、`parseTable_ =` | 27/5 | 否 |

其中生产头文件 `tools/process_dump/minidump_parser/include/minidump_factory.h` 已被
成功检索；测试目录没有进入本次扫描候选列表。

### 回归测试

命令覆盖恢复器、投影器、逐轮调度器、scanner 集成和本切片：

```text
.venv/bin/python -m pytest -q \
  libs/openant-core/tests/openharmony/test_llm_call_graph_recovery.py \
  libs/openant-core/tests/openharmony/test_llm_call_graph_projection.py \
  libs/openant-core/tests/openharmony/test_llm_call_graph_rounds.py \
  libs/openant-core/tests/openharmony/test_registration_context.py \
  libs/openant-core/tests/test_scanner_llm_recovery_integration.py
```

结果：`36 passed in 0.70s`；Ruff 检查通过。

## 限制

- 当前仍是文本/符号检索，不理解宏展开、模板实例化或构建条件；
- `MinidumpStreamFactory` 的生产上下文虽然被找回，但 16,000 字符预算下会发生截断，
  下一切片需要对注册语句进行优先级排序并压缩重复函数片段；
- 目前收集结果还没有加入 `build_recovery_worklist()` 和 `build_recovery_prompt()`，
  因此真实模型恢复行为尚未改变。

