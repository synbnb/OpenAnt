# OH-SL-01A：目标标准化与初始查询测试记录

日期：2026-08-28
阶段：源码定位器 SL-01A（目标标准化和固定初始查询）
目标：把用户提供的 OpenHarmony 服务描述转换成安全、可审计的 `TargetSpec`，并生成不依赖 LLM 的有限 OpenGrok 初始查询序列。

## 1. 原项目逻辑与修改后逻辑

原项目没有源码定位器目标对象。用户如果要扫描 OpenHarmony 仓库，需要先手工知道本地仓库路径；OpenGrok 客户端也没有统一的自然语言输入和固定查询计划。

修改后增加 `core/source_locator/target_normalizer.py`：

```text
用户描述
  → Unicode/空白/中文标点清洗
  → 提取 Unix socket 路径、宏/常量赋值或服务名
  → 拒绝 URL、控制字符、路径穿越和疑似本地工程路径
  → 生成 TargetSpec
  → 生成有顺序、去重、有长度上限的 OpenGrok 查询
```

例如：

```text
我想分析‘/dev/unix/socket/paramservice’。
```

会得到：

```json
{
  "target_type": "unix_socket",
  "socket_path": "/dev/unix/socket/paramservice",
  "basename": "paramservice",
  "service_hint": "paramservice",
  "target_revision": "unknown",
  "path_components": ["dev", "unix", "socket", "paramservice"]
}
```

对：

```text
PIPE_NAME = "/dev/unix/socket/paramservice"
```

会同时保留 `macro_hint=PIPE_NAME` 和 socket 路径，后续查询优先搜索宏定义/引用，再搜索 basename 和完整路径。

查询计划固定使用 OpenGrok 的 `def`、`symbol`、`path`、`full` 字段，并且 C++ 类型明确使用 `cxx`，不使用容易产生零结果的 `cpp`。默认最多 12 条查询；每条查询带 `Q-0001` 形式的 ID、查询原因和参数映射，方便后续证据追踪。

## 2. 安全和边界

- 输入为空、过长或含控制字符时立即报错；
- URL（`http://`、`https://`、`file://`）不会被提取成伪 socket；
- `/Users/...`、`/home/...`、`/private/...`、`source_code_base` 等本地工程路径不会被误判为远程 Unix socket；这类输入继续使用原有直接本地扫描入口；
- socket 路径拒绝反斜杠、query/fragment、空组件、`.` 和 `..`；
- Git revision 只能来自调用方或配置，默认值是显式的 `unknown`，不会由标准化器猜测分支；
- 查询值和查询数量均有限制，重复查询被去重；
- 本阶段不调用 LLM、不访问网络、不判断服务端归属、不推断 GitCode 仓库。

标准化器只产生“检索种子”，不把服务名直接当成仓库名，也不把一次全文命中当成定位结论。

## 3. 文件变更

- `libs/openant-core/core/source_locator/target_normalizer.py`
- `libs/openant-core/core/source_locator/__init__.py`
- `libs/openant-core/tests/source_locator/test_target_normalizer.py`

## 4. 独立测试

执行：

```text
cd libs/openant-core
../../.venv/bin/python -m pytest -q \
  tests/source_locator/test_target_normalizer.py \
  tests/source_locator/test_config.py \
  tests/source_locator/test_opengrok_live_fixture_contract.py \
  tests/test_opengrok_client.py \
  tests/test_opengrok_protocol_models.py \
  tests/test_llm_config_schema.py
```

结果：`70 passed in 0.09s`。

覆盖内容包括：

- 中文标点包裹的完整 socket 路径；
- `PIPE_NAME=/dev/unix/socket/paramservice` 宏赋值；
- 无路径的宏名和服务名；
- 本地绝对路径拒绝；
- 空输入、URL、控制字符、路径穿越和不可识别描述；
- 查询顺序稳定、ID 连续、结果去重、数量/长度受限；
- `c`/`cxx` 类型选择和不出现 `cpp`；
- revision 和 `max_queries` 边界；
- SL-00B 配置模型、SL-00A 真实响应回放及已有 OpenGrok 客户端回归。

静态检查：

```text
.venv/bin/ruff check \
  libs/openant-core/core/source_locator/target_normalizer.py \
  libs/openant-core/core/source_locator/__init__.py \
  libs/openant-core/tests/source_locator/test_target_normalizer.py
```

结果：`All checks passed!`；Python `compileall` 和 `git diff --check` 均通过。

## 5. 结论与后续边界

SL-01A 已建立不依赖大模型的目标输入契约和初始检索种子，能够稳定处理当前 `/dev/unix/socket/paramservice` 类目标。它还不能根据搜索结果判断 creator、owner、consumer 或 GitCode 仓库；这些必须在后续 OpenGrok 检索、候选排序和证据图阶段实现。

下一阶段建议执行 SL-01B：将这些 `LocatorQuery` 逐条接入现有 `OpenGrokClient`，并用 SL-00A 的真实响应夹具验证搜索参数和回放结果。
