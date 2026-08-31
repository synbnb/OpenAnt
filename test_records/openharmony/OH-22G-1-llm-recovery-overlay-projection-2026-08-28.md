# OH-22G-1：LLM 调用图恢复边独立投影

## 阶段目标

为 LLM 调用图恢复结果增加一个独立的、可审计的 semantic overlay 投影边界。该阶段不修改原生调用图、不修改扫描器主流程、不改变 reachable 数据集。

## 实现内容

- 新增 LLM 恢复边投影模块；
- 只接受高置信度 `add_edge` 决策；
- 二次检查 caller/target/site ID、候选列表、检索候选和证据类型；
- 要求调用点证据与残余表达式、文件和行号一致；
- 要求目标/注册证据能对应目标函数或目标方法名；
- 输出独立的 `llm_confirmed_indirect_call` 边；
- 低置信度、未知目标、错误证据和重复边写入 rejected 记录；
- 输入报告和函数索引保持不变；
- 输出可被现有 `SemanticGraph` 重新读取。

## 测试环境

- Python：项目独立虚拟环境；
- 测试范围：OpenHarmony 相关单元测试；
- 测试日期：2026-08-28。

## 测试记录

### 1. 投影模块及恢复协议回归

```text
python -m pytest -q
  tests/openharmony/test_llm_call_graph_projection.py
  tests/openharmony/test_llm_call_graph_recovery.py
  tests/openharmony/test_llm_recovery_execution.py
```

结果：13 passed。

覆盖内容：

- 合法高置信度边投影；
- 低置信度边拒绝；
- 目标不在候选列表时拒绝；
- 调用点证据不足时拒绝；
- 重复 caller-target 边只投影一次；
- 缺失 validation 区块时返回 invalid；
- 输入对象不被修改；
- overlay 可被 `SemanticGraph.from_dict()` 读取。

### 2. 真实 OpenHarmony 产物回放

使用 `sensors_medical_sensor` 的真实 candidate-edge review 产物和对应调用图进行离线回放，不重新调用模型、不修改原始产物。

结果：

```text
accepted 输入边：8
投影边：8
拒绝：0
重复边：0
状态：complete
```

这说明当前投影边界可以消费真实模型结果；它不证明这 8 条边在所有源码版本中都正确，也不证明未被模型 accepted 的边不存在。

### 3. 完整 OpenHarmony 回归

```text
python -m pytest -q tests/openharmony
```

结果：149 passed，2 skipped，0 failed。

## 当前限制

本阶段只产生独立 overlay。`llm_call_graph_recovery` 和 `llm_call_graph_candidate_review` 仍不会自动写回 `call_graph.json`，也不会自动改变 reachable 或 Web 调用图。下一阶段需要在用户确认后，将该 overlay 以显式开关接入扫描器，并增加单调性检查和 BFS 回归测试。

