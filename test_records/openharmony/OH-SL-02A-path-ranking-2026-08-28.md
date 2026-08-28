# OH-SL-02A：OpenGrok 候选路径分类与排序测试记录

日期：2026-08-28
阶段：源码定位器 SL-02A（路径分类、降噪和可解释排序）
目标：对 OpenGrok 搜索返回的生产源码、生成物、测试资源、SELinux 策略、内核相关路径、日志和第三方代码进行可解释排序，不因为类别判断而静默删除候选。

## 1. 原项目逻辑与修改后逻辑

原项目的 `OpenGrokClient` 和 `SearchPlanner` 只保存搜索返回顺序及结果文件，没有路径角色或候选优先级。真实全文搜索会把生产代码、构建输出、SELinux 策略和测试资源混在一起，直接把结果交给后续分析会产生大量噪声。

修改后新增 `core/source_locator/path_classifier.py`：

```text
OpenGrok 路径列表
  → 校验远程路径安全性
  → 识别 production/test/fuzz/generated/build/selinux/kernel/log/third_party/unknown
  → 计算目标标识、服务目录、源码目录等正向特征
  → 计算类别降权特征
  → 按 score 降序、path 字典序稳定排序
  → 保留全部候选并返回特征明细
```

角色权重不是隐藏判断。每个结果都包含 `role`、`score` 和 `features[{code,label,weight}]`，后续 Web 可以直接解释“为什么排在这里”。目标 basename 与文件名的精确匹配权重大于目标前缀匹配；前缀只能提高候选顺序，不能证明服务归属。

## 2. 真实 94 条搜索结果

在已验证的 OpenGrok 1.14.11 实例上只读执行：

```text
full=/dev/unix/socket/paramservice
project=openharmony
max_results=100
max_hits_per_file=1
```

实际返回 94 个文件。新增的 `search_full_paramservice_paths.json` 只保存路径清单和查询元数据，不保存源码正文、Cookie 或认证信息；与再次只读请求相比，路径集合完全一致（OpenGrok 结果顺序可能变化）。

分类后的角色统计为：

```text
generated：76
selinux：11
test：6
production：1
```

真实清单中的生产候选是：

```text
/openharmony/base/startup/init/services/param/include/param_utils.h
```

它被排在生成物和 SELinux 策略之前，并保留“生产头文件包含宏/常量定义”的解释特征。生成的 `out/` 二进制、SELinux `.te`/上下文文件和测试 `last_kmsg` 文件均未删除，只是降低优先级。

## 3. 安全边界

- 候选路径拒绝空值、URL、反斜杠、query/fragment、控制字符、超长路径和 `..` 穿越片段；
- 不把 `linux` 目录一概判为内核，只有明确的 `kernel`/内核头/内核产物线索才归入 kernel；
- 目标匹配只影响排序，不直接确认服务端归属；
- 重复路径只做精确路径去重，角色被降权的候选仍会出现在结果中；
- 本阶段不读取源码、不调用 LLM、不创建证据边、不映射仓库或执行 clone。

## 4. 文件变更

- `libs/openant-core/core/source_locator/path_classifier.py`
- `libs/openant-core/core/source_locator/__init__.py`
- `libs/openant-core/tests/source_locator/test_path_classifier.py`
- `libs/openant-core/tests/source_locator/fixtures/opengrok/live_1_14_11/search_full_paramservice_paths.json`
- `libs/openant-core/tests/source_locator/test_opengrok_live_fixture_contract.py`（登记新增路径清单夹具）

## 5. 独立测试

执行：

```text
cd libs/openant-core
../../.venv/bin/python -m pytest -q \
  tests/source_locator/test_path_classifier.py \
  tests/source_locator/test_search_planner.py \
  tests/source_locator/test_target_normalizer.py \
  tests/source_locator/test_config.py \
  tests/source_locator/test_opengrok_live_fixture_contract.py \
  tests/test_opengrok_client.py \
  tests/test_opengrok_protocol_models.py \
  tests/test_llm_config_schema.py
```

结果：`96 passed in 0.10s`。

覆盖内容包括：

- 生产 C/C++ 实现和头文件的角色及目标匹配特征；
- test、fuzz、generated、build、SELinux、kernel、log、third-party 和 unknown 分类；
- 真实 94 条全文搜索路径全部保留，生产头文件优先于生成物和 SELinux；
- 分数特征明细、稳定排序和精确重复路径去重；
- 远程 URL、路径穿越、控制字符、反斜杠和长度上限拒绝。

静态检查：

```text
.venv/bin/ruff check \
  libs/openant-core/core/source_locator/path_classifier.py \
  libs/openant-core/core/source_locator/__init__.py \
  libs/openant-core/tests/source_locator/test_path_classifier.py \
  libs/openant-core/tests/source_locator/test_opengrok_live_fixture_contract.py
```

结果：`All checks passed!`；Python `compileall` 和 `git diff --check` 均通过。

## 6. 结论与边界

SL-02A 已证明真实全文结果可以在不丢失候选的前提下完成路径降噪和透明排序。当前排序只利用路径和目标标识，不能从路径本身确认 socket 服务消费者；下一阶段 SL-02B 需要读取高排名候选源码，建立带行号和来源端点的 EvidenceStore/EvidenceGraph。
