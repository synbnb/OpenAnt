# OH-22C-1：LLM 调用边恢复协议与残余筛选测试记录

日期：2026-08-27  
范围：OpenHarmony 间接调用残余的 LLM 辅助前置协议  
参考产物：`debug_outputs/OH-22B-2I-all-20260827`

## 1. 阶段目标

上一阶段已经用确定性规则恢复了可证明的成员函数表和局部数组参数流，但仍有一批
函数指针、模板成员指针和 Lambda/Callable 调用无法从语法直接确定目标。本阶段先建立
一个安全的 LLM 边恢复边界，不把模型输出直接写入调用图：

```text
残余调用点
  → 只选无确定性候选的点
  → 生成有限函数索引检索候选
  → 构建带源码证据的严格提示词
  → 解析模型 JSON
  → 校验 site/target ID、置信度和源码证据
  → accepted_for_review（暂不投影 SemanticGraph）
```

## 2. 修改前后的逻辑

### 修改前

1. `call_graph_residuals.json` 只保存残余调用点和确定性候选；
2. 项目现有 `--llm-reachability` 只分析“哪些函数可能是入口”，不会分析
   `caller → target` 调用边；
3. 没有面向调用边的 LLM 输入格式、目标函数索引范围、证据要求和拒绝策略。

### 修改后

新增 `core/platforms/openharmony/llm_call_graph_recovery.py`，提供四组纯函数：

- `build_recovery_worklist`：默认只选 `candidate_target_ids=[]` 的残余，生成稳定的
  `site_id`、调用函数源码、调用表达式、平台边界优先级和最多 12 个检索候选；
- `build_recovery_prompt`：要求模型只能从检索候选中选目标，必须返回调用点及目标/注册
  证据，提示词使用长度自适应代码围栏；
- `parse_recovery_response`：严格检查 schema、site ID、target ID、decision、confidence
  和非空证据，未知 ID、重复项和格式错误均丢弃；
- `validate_recovery_proposals`：再次验证目标函数存在、置信度达到阈值、调用点和目标/注册
  源码证据同时存在，输出 `accepted`、`kept_unresolved`、`rejected` 三类结果。

另有 `security_relevant_only=True` 成本控制模式，仅保留已知入口点或包含 IPC、Binder、
SystemAbility、socket、request 等边界信号的残余；它是优先级筛选，不是安全结论。

本阶段不调用真实模型、不修改 `call_graph.json`、不修改 `SemanticGraph`，因此不会把模型
幻觉边混入现有确定性结果。

## 3. 测试驱动过程

新增测试文件：

```text
libs/openant-core/tests/openharmony/test_llm_call_graph_recovery.py
```

覆盖以下行为：

1. 无候选残余进入工作队列，已有候选的站点默认排除；
2. `OnRemoteRequest` 被标记为高优先级边界；
3. `security_relevant_only` 可以排除普通后台回调；
4. 不可信表达式中的反引号不能破坏提示词代码围栏；
5. 未知 site/target、重复 decision、缺失证据会被拒绝；
6. 低置信度边不会进入默认 `accepted` 集合；
7. 输入诊断数据保持不变。

定向测试：

```bash
source .venv/bin/activate
pytest -q libs/openant-core/tests/openharmony/test_llm_call_graph_recovery.py
# 4 passed

ruff check \
  libs/openant-core/core/platforms/openharmony/llm_call_graph_recovery.py \
  libs/openant-core/tests/openharmony/test_llm_call_graph_recovery.py
# All checks passed!
```

## 4. 真实 OpenHarmony 残余 dry-run

输入为 OH-22B-2I 9 个仓库 all 模式的 `call_graph.json` 和
`call_graph_residuals.json`，没有 API 调用：

| 仓库 | 无候选残余 | 边界筛选后 | 筛选后提示词字符数 |
|---|---:|---:|---:|
| communication_netmanager_base | 2 | 0 | 877（空队列） |
| developtools_hdc | 0 | 0 | 877（空队列） |
| hiviewdfx_faultloggerd | 1 | 0 | 877（空队列） |
| hiviewdfx_hilog | 0 | 0 | 877（空队列） |
| hiviewdfx_hiview | 19 | 0 | 877（空队列） |
| multimedia_audio_framework | 55 | 3 | 58,274 |
| startup_appspawn | 1 | 0 | 877（空队列） |
| startup_init | 0 | 0 | 877（空队列） |
| telephony_core_service | 11 | 2 | 29,695 |
| **合计** | **89** | **5** | **87,090** |

未筛选的 89 个点仍可以通过 `security_relevant_only=False` 生成完整审计工作队列；默认
优先模式只把 5 个可能与边界相关的点交给后续 LLM 阶段。所有工作项的检索候选最多 12
个，当前没有任何模型结果被接受或写回图。

## 5. 与现有 LLM 可达性阶段的关系

`--llm-reachability` 当前仍只产生 `entry_point`、`external_input`、`cross_process` 三类
单元信号，并用高置信度入口重新执行 BFS。它不会读取本协议的 worklist，也不会产生
`caller → target` 边。本阶段是未来独立 `llm-call-graph-recovery` 阶段的输入/验证层。

## 6. 完整 OpenHarmony 专项测试

```bash
source .venv/bin/activate
pytest -q libs/openant-core/tests/openharmony
# 116 passed, 2 skipped
```

其中包括此前 OH-22B-2I 的成员数组参数流、Native resolver 和全部平台适配回归。

## 7. 当前边界和后续接入条件

1. 本阶段没有声称已经恢复 89 个无候选点；它只建立可审计的模型输入和结果校验协议；
2. 检索候选是上下文，不是证明，模型不能仅凭名字选择目标；
3. 只有目标 ID 存在、调用点与目标/注册证据齐全、置信度达到阈值的 proposal 才能进入
   后续人工/程序复核；
4. 运行时注入、外部库回调、反射/生成代码和无法唯一确定的模板实例仍应保持残余；
5. 下一阶段如果接入真实模型，应增加 API 重试、缓存、成本上限、模型一致性复核以及
   通过验证后再投影 SemanticGraph 的逻辑，并单独在
   `multimedia_audio_framework` 和 `telephony_core_service` 上评估精确率与召回率。

## 8. 阶段结论

OH-22C-1 已完成 LLM 调用边恢复的安全前置层。它把 135 个间接调用观察点中真正无确定
候选的 89 个点显式分离，并提供了默认 5 点的边界优先工作队列；现有确定性调用图和
SemanticGraph 不受影响。是否把通过校验的 proposal 投影为语义边，应在真实模型小规模
试验并完成精确率/召回率评估后另设阶段决定。
