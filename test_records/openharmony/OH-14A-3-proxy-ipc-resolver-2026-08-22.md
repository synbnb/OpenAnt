# OH-14A-3：Proxy 侧 IPC transaction 解析

日期：2026-08-22  
阶段：OH-14A-3  
范围：补齐 IDL/native IPC 图的客户端 Proxy → transaction 边；不接入 scanner/reachability，不处理 SA 绑定。

## 1. 原逻辑与修改逻辑

OH-14A-2 只能从服务端 `OnRemoteRequest` 或 dispatch table 找到 transaction，跨进程链路缺少客户端发起方：

```text
客户端 Proxy → SendRequest → transaction → 服务端 handler
```

本阶段修改为：

1. 识别 `SendRequest`、`SendRequestAsync` 等调用及其函数上下文；
2. 识别 `CMD_*`、`COMMAND_*`、`SERVICE_CMD_*`、`TRANSACTION_*`、`SERVICE_TRANSACTION_*` 等 transaction token；
3. 支持 `TriggerSyncInner` → `SERVICE_CMD_TRIGGER_SYNC` 这类 OpenHarmony 常见的 CamelCase/枚举命名差异，并对 `Inner/Impl` 后缀生成基础 token；
4. 生成 `proxy_to_transaction` 边，保留 Proxy 文件、行号、匹配 token、调用名和置信度；
5. Proxy 函数不会被当作服务端 dispatch。没有 Proxy 证据或存在多候选时写入 `unresolved_ipc_proxy`/`ambiguous_ipc_proxy` orphan；
6. 服务端原有 `stub_to_transaction` 和 `transaction_to_handler` 逻辑保持不变。

## 2. 修改文件

- `libs/vulnfounder-core/core/platforms/openharmony/ipc_graph.py`
  - 增加 Proxy 候选解析和 `proxy_to_transaction` 边；
  - 增加常见 OpenHarmony transaction token 命名变体；
  - 排除包含 `SendRequest` 的函数被误判为 dispatch table。
- `libs/vulnfounder-core/tests/platforms/test_openharmony_ipc_graph.py`
  - 增加 Proxy 正例、Proxy/Stub 角色隔离和 token 命名回归测试。

## 3. 测试结果

Proxy resolver 专项：

```text
../../.venv/bin/python -m pytest tests/platforms/test_openharmony_ipc_graph.py -q
7 passed in 0.02s
```

OpenHarmony 与 C parser 回归：

```text
../../.venv/bin/python -m pytest \
  tests/platforms tests/openharmony tests/parsers/c -q
178 passed, 6 skipped in 0.51s
```

另外执行了 `py_compile`（resolver 及测试文件）和 `git diff --check`，均通过。

## 4. fixture 验证

Proxy fixture：

```cpp
int HealthServiceProxy::Enable(...)
{
    return remote->SendRequest(COMMAND_ENABLE, data, reply, option);
}
```

解析结果包含：

```text
function:HealthServiceProxy::Enable
    └─proxy_to_transaction─>
idl:transaction:OHOS.Health.IHealthService:Enable
```

同一 fixture 中的 `HealthServiceStub::OnRemoteRequest` 仍单独生成 `stub_to_transaction`，而 Proxy 不会生成 `stub_to_transaction`。只有同名 `OtherService::Enable` 且没有 `SendRequest`/transaction 证据时不会被连接。

## 5. 真实仓库验证

对本地真实仓库 `filemanagement_dfs_service` 执行 production 范围扫描、C/C++ 函数提取、IDL 收集和 resolver：

| 项目 | 数量 |
|---|---:|
| production C/C++ 文件 | 570 |
| native 函数 | 4,205 |
| IDL 文件 | 2 |
| IDL interface | 2 |
| IDL methods | 73 |
| 图节点 | 76 |
| 图边 | 74（73 `interface_to_transaction`、1 `proxy_to_transaction`） |
| `unresolved_ipc_proxy` | 72 |
| `unresolved_ipc_stub` | 73 |

实际识别到：

```text
CloudSyncServiceProxy::TriggerSyncInner
  → ICloudSyncService::TriggerSyncInner
  → SERVICE_CMD_TRIGGER_SYNC
```

该边置信度为 `0.95`，证据来自真实文件：
`frameworks/native/cloudsync_kit_inner_lite/src/cloud_sync_service_proxy_lite.cpp` 第 49 行附近的 `SendRequest` 和 `SERVICE_CMD_TRIGGER_SYNC`。

当前 production 范围没有对应生成服务端 stub，因此 73 个服务端缺口仍被逐项记录，没有根据 Proxy 名称伪造 handler 边。

## 6. 结论与边界

OH-14A-3 已完成客户端 Proxy 到 IPC transaction 的确定性关联。现在语义图可以同时表达 IDL contract、客户端请求发起点和服务端 dispatch 入口。

尚未处理：SA profile 与 IDL/interface 的关联、Proxy 与服务端跨进程闭环的主流程接入、生成代码缺失时的宏/枚举跨文件推理，以及 scanner/reachability 对语义图的消费。这些继续拆分为后续阶段。
