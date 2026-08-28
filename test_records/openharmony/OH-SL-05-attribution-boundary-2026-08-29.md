# OH-SL-05：服务端归因与客户端通信边界

日期：2026-08-29
阶段：源码定位前置流程（SL-05）
模型调用：0 次
Git 操作：未执行
动态测试：未执行

## 1. 本阶段目标

OpenGrok 命中可能同时包含 init/socket 创建线索、服务端实现、客户端通信代码和上层
业务调用者。本阶段在已有 `EvidenceStore` 上增加确定性的角色归因，区分：

- 服务端：`socket_creator`、`service_owner`、`server_consumer`、`server_handler`；
- 客户端：`client_transport`、`client_protocol`、`client_sender`。

目标是避免把“创建了 socket 的 init 代码”误当真正服务端，也避免在客户端通信层已经
确认后继续扩大到所有业务 caller。

## 2. 修改前后的逻辑

### 修改前

1. 证据只能按 kind 保存和计分，调用方需要自行解释 `socket_acquire`、`read`、`send`
   等证据属于哪个角色。
2. 数值分数与服务端确认逻辑没有形成可复用的 server/client 结果对象。
3. 没有统一的“客户端通信已完成”状态，也没有阻止后续 `find_business_callers` 的契约。

### 修改后

1. `ServiceAttributor` 将证据按源码主体（`relation_to`、symbol 或路径/行号）归并成
   服务端候选，并保存源码位置、证据 ID、角色和解释原因。
2. 服务端只有同时满足以下硬性条件才是 `HIGH`/confirmed：

   ```text
   socket_identity
   AND socket_acquire 或 bind/listen
   AND accept/read/recv 或 protocol_dispatch
   AND 已解析 Manifest mapping
   ```

   只有 `service_config`、`socket_acquire` 或 bind 线索时最多是 `PARTIAL`，不会确认
   server。没有服务相关证据时为 `UNRESOLVED`。
3. 服务端分数固定为可解释谓词分数（身份 15、服务关系 15、获取或监听 25、消费 25、
   分派 10、Manifest 10），分数仅用于排序和展示，不能绕过硬性条件。
4. `ClientLocator` 要求目标关系、endpoint/connect（允许 endpoint 作为明确等价证据）、
   协议/请求构造、发送以及已解析 Manifest mapping。满足后返回 `HIGH`/completed。
5. 客户端完成结果显式声明禁止 `find_business_callers`；`allows_action()` 返回 false，
   `assert_action_allowed()` 会拒绝该动作。普通只读动作仍可继续。
6. 服务端和客户端任一侧未完成时，`combine_attributions()` 返回 `PARTIAL`；例如
   `server=HIGH`、`client=UNRESOLVED` 不会伪造成完整 HIGH。
7. 所有输入必须是已验证的 `Evidence`、`EvidenceStore` 或 `RepositoryMapping`，非布尔
   谓词、非法角色和错误类型会显式报错；不调用模型、不访问网络、不执行 Git。

## 3. 涉及文件

- `libs/openant-core/core/source_locator/service_attributor.py`
  - 新增服务端候选、源码位置、服务端结果和 server/client 汇总状态契约。
- `libs/openant-core/core/source_locator/client_locator.py`
  - 新增客户端传输/协议/发送定位，以及业务 caller 动作门禁。
- `libs/openant-core/core/source_locator/__init__.py`
  - 导出两个定位器和结果类型。
- `libs/openant-core/tests/source_locator/test_service_attributor.py`
  - 服务端 creator-only、fd→receive→dispatch、映射冲突和输入边界夹具。
- `libs/openant-core/tests/source_locator/test_client_locator.py`
  - 客户端完成、等价 endpoint、目标关系缺失、业务 caller 门禁和整体状态夹具。

## 4. 独立测试

工作目录：`libs/openant-core`
Python 环境：项目独立环境 `.venv`

### 4.1 SL-05 定向测试

```text
../../.venv/bin/pytest -q \
  tests/source_locator/test_service_attributor.py \
  tests/source_locator/test_client_locator.py
```

结果：`19 passed in 0.05s`。

覆盖的关键断言：

- creator-only 不会成为 confirmed server；
- `fd acquire → accept/read → protocol_dispatch` 可确认服务端；
- 缺少 identity、消费证据或已解析 mapping 时保持 `PARTIAL`；
- client endpoint/connect + protocol + send 可完成；
- 客户端完成后 `find_business_callers` 被拒绝；
- server HIGH + client UNRESOLVED 的整体状态为 `PARTIAL`；
- 重复 Evidence ID 不增加分数；
- 非布尔 predicates、非法 mapping 和错误输入显式失败。

### 4.2 源码定位器回归

```text
../../.venv/bin/pytest -q tests/source_locator
```

结果：`182 passed in 0.12s`。

### 4.3 静态检查

```text
../../.venv/bin/ruff check core/source_locator tests/source_locator
../../.venv/bin/python -m compileall -q core/source_locator tests/source_locator
```

结果：Ruff `All checks passed`；Python 编译检查无输出并成功完成。

## 5. 真实 OpenHarmony 源码契约回放

使用本地参考仓库 `openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd`
中的已核对行，仅用于验证证据契约能够表达真实代码结构；角色 kind 由测试脚本依据源码
位置显式标注，不把这次回放当成自动规则识别准确率证明。

选取的实际证据包括：

- `interfaces/common/dfx_socket_request.h:33`：服务 socket 名称常量；
- `services/fault_logger_server.cpp:98`：服务端 `StartListen`；
- `services/fault_logger_server.cpp:136`、`:165`：`read` 与 `accept`；
- `services/fault_logger_server.cpp:142`：按 client type 获取服务并分派；
- `interfaces/innerkits/faultloggerd_client/faultloggerd_client.cpp:39`：客户端 socket 名称；
- `interfaces/innerkits/faultloggerd_client/faultloggerd_socket.cpp:194`：`connect`；
- `interfaces/innerkits/faultloggerd_client/faultloggerd_client.cpp:64`：请求结构构造；
- `interfaces/innerkits/faultloggerd_client/faultloggerd_socket.cpp:279`：写入请求。

回放结果：`server=HIGH(score=85)`、`client=HIGH(score=100)`、`overall=HIGH`。服务端
分数为 85 是因为该回放没有额外标注 `service_config/executable_build`，但硬性服务端
谓词全部满足；这说明分数与确认条件保持分离。

## 6. 结果与边界

本阶段完成了可解释的 server/client 角色归因和通信边界门禁，为后续受限 LLM Search
Planner 提供了稳定输入。它不声称能从任意原始文本自动判定证据 kind；证据采集与
OpenGrok 查询规划仍由后续阶段接入。映射结果也只是归因输入，尚未触发拉取或静态分析。
