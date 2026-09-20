# OH-22G-3：LLM 调用图叠加接入 semantic reachable 测试记录

日期：2026-08-28  
阶段：OH-22G-3（第 2B 小阶段）  
目标：将 OH-22G-2 生成的独立 LLM 调用图叠加，以只增不减的方式接入 reachable BFS。

## 原逻辑与本阶段逻辑

原流程的 reachable 过滤读取原生 `call_graph.json`，并在 OpenHarmony
场景下可选地读取确定性 `semantic_graph.json`。LLM 调用边审核结果即使存在，
也不会影响数据集过滤。

本阶段新增：

- `apply_reachability_filter(..., semantic_graph_overlay=...)` 接口；
- `llm_confirmed_indirect_call` 语义边类型白名单；
- 确定性语义图和 LLM 叠加图分别解析，再合并到内存 reverse graph；
- 扫描器在 `--llm-call-graph-projection` 且 level 不是 `all` 时保存
  `dataset_unfiltered.json`，投影完成后从全量数据集重新执行 reachable 过滤；
- 多语言场景按语言函数索引选取对应 overlay，无法匹配时不猜测；
- 原生可达集合单调保留，LLM 边只能增加可达函数，不能裁剪原有函数；
- LLM reachability 阶段已设置的入口标记和信号在重新过滤后恢复。

未改变：

- `call_graph.json` 不被写回；
- `semantic_graph.json` 不被覆盖；
- 未开启投影开关时，原有流程不读取 LLM overlay；
- malformed overlay 只产生警告并降级为原生/确定性图。

## 自动化测试

命令：

```text
.venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony/test_semantic_reachability_overlay.py \
  libs/vulnfounder-core/tests/test_scanner_llm_recovery_integration.py \
  libs/vulnfounder-core/tests/openharmony/test_llm_call_graph_projection.py
```

结果：`26 passed`。

覆盖内容：

1. parser adapter 使用 LLM overlay 后，原生入口和原生可达函数仍保留，新增目标函数可被 BFS 找到；
2. LLM 边类型被正确接收并写入 `semantic_overlay` 元数据；
3. malformed overlay 不会破坏原生 reachable 结果；
4. 扫描器在 reachable 模式下从全量 sidecar 重新过滤，新增目标进入 `dataset.json`；
5. 没有恢复产物时，投影阶段生成 `no_artifacts` 记录，但 reachable 仍保持基线过滤；
6. generic 平台安全跳过；
7. Python CLI 投影开关默认关闭并正确转发。

静态检查：

- `py_compile` 通过；
- `ruff check` 通过；
- `git diff --check` 通过。

Go CLI 已增加三个转发开关：

- `--llm-call-graph-recovery`；
- `--llm-call-graph-candidate-review`；
- `--llm-call-graph-projection`。

当前环境未安装 Go 工具链（`go`/`gofmt` 不在 PATH），因此 Go 单测未能在本机执行；Go 代码保持现有格式和最小转发改动，待具备 Go 工具链的环境补跑。

## 真实 OpenHarmony 回放

使用之前真实 `sensors_medical_sensor` 运行产生的文件，未调用模型：

- 函数索引：340 个函数；
- 真实恢复审核 + 候选审核：2 个源产物；
- LLM 投影：8 条高置信度边，8/8 通过，0 拒绝，0 未匹配；
- 原生 BFS：11 个可达函数；
- 加入确定性语义图和 LLM overlay 后：25 个可达函数；
- `semantic_reachable_added`：14；
- semantic overlay edge count：8。

进一步逐对比较发现，8 条 LLM 边全部与已有确定性
`native_dispatch_to_handler` 边重合，LLM 在该样本上没有额外增加可达函数。
这证明接入和单调性正确，但不能把该样本宣称为 LLM 带来新增召回的证据。

## 已知限制

- 本阶段只消费已经审核并通过证据验证的边，不会在 BFS 每到一个新函数时自动发起下一轮模型复核；
- 如果仓库没有可识别的真实入口，现有空种子安全策略仍会保留全部单元，不会由调用边凭空制造入口；
- Go 单测需在安装 Go 后补跑；
- 全量 Python 测试包含已有的本地 LLM/HTTP 集成测试，早期会长时间占用 localhost 连接，未作为本阶段离线回归依据。

## 结论

OH-22G-3 已完成。LLM 调用图叠加现在可以在显式开关下参与 OpenHarmony
reachable BFS，并具备原生图单调性、来源可审计和坏输入安全降级保证。下一阶段
应评估入口驱动的逐层残余复核，而不是直接默认开启该功能。
