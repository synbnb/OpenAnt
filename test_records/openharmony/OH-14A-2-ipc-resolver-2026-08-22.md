# OH-14A-2：OpenHarmony IPC resolver

日期：2026-08-22  
阶段：OH-14A-2  
范围：在 OH-14A-1 语义图容器上实现 IDL 到 C/C++ IPC dispatch/handler 的确定性解析；暂不接入 scanner/reachability。

## 1. 原逻辑与修改逻辑

原逻辑只有语言内 C/C++ 调用图和独立 IDL 元数据，无法表达：

```text
IDL interface/method → Binder transaction → OnRemoteRequest/dispatch → native handler
```

修改后新增 `OpenHarmonyIPCResolver`：

1. 为 IDL interface 和每个 method 创建 `idl_interface`、`ipc_transaction` 节点；
2. 为每个 IDL 方法创建 `interface_to_transaction` 边，保留 IDL 路径、行号、返回类型和参数方向；
3. 在 C/C++ 函数中识别 `OnRemoteRequest` 的方法调用/transaction token，以及构造函数或 dispatch table 中的 `CMD_*`、`TRANSACTION_*`、`CODE_*` 和 handler 引用；
4. 生成 `stub_to_transaction` 和 `transaction_to_handler` 边，每条边带 native 文件、行号、匹配信号、置信度和 resolver version；
5. 仅有同名函数但没有 dispatch 证据时不连边；无法解析或存在歧义时写入 `unresolved_*`/`ambiguous_*` orphan；
6. 匹配前屏蔽注释和字符串字面量，重载 IDL 方法使用稳定的 `:overload:N` transaction ID。

这一步仍然是确定性静态证据，不把“名称相似”当作高置信度 IPC 事实，也没有改变现有入口检测或 reachable 过滤结果。

## 2. 修改文件

- `libs/openant-core/core/platforms/openharmony/ipc_graph.py`
  - 新增 `OpenHarmonyIPCResolver`/`IPCGraphResolver`；
  - 支持 dataclass 或字典形式的 IDL 结果、普通函数映射和完整 extractor 输出；
  - 支持直接 `OnRemoteRequest` dispatch 与 transaction table 初始化两类证据。
- `libs/openant-core/tests/platforms/test_openharmony_ipc_graph.py`
  - 增加正例、transaction table、同名误报、注释/字符串、orphan、重载方法和序列化测试。

本阶段没有修改 generic 平台、C/C++ parser、入口检测器或 reachability 主流程。

## 3. 定向测试结果

resolver 专项测试：

```text
../../.venv/bin/python -m pytest tests/platforms/test_openharmony_ipc_graph.py -q
6 passed in 0.02s
```

平台回归：

```text
../../.venv/bin/python -m pytest tests/platforms tests/openharmony -q
78 passed, 6 skipped in 0.09s
```

OpenHarmony 与 C parser 回归：

```text
../../.venv/bin/python -m pytest \
  tests/platforms tests/openharmony tests/parsers/c -q
177 passed, 6 skipped in 0.49s
```

另外执行了 `py_compile`（graph、resolver 及其测试文件）和 `git diff --check`，均通过。

## 4. fixture 验证

fixture 中的 IDL 方法 `OHOS.Health.IHealthService::Enable` 与以下 native 代码对应：

```cpp
HealthServiceStub::OnRemoteRequest(...) {
    switch (code) {
        case CMD_ENABLE:
            return Enable(data, reply);
    }
}
```

解析结果包含：

```text
idl:interface:OHOS.Health.IHealthService
    └─interface_to_transaction─>
idl:transaction:OHOS.Health.IHealthService:Enable
    ├─stub_to_transaction  <─ function:...HealthServiceStub::OnRemoteRequest
    └─transaction_to_handler─> function:...HealthServiceStub::Enable
```

同一 IDL 下的 `OtherService::Enable` 不会被连接，因为 owner 不匹配；只有注释或字符串中出现 `CMD_ENABLE/Enable` 也不会被连接。

## 5. 真实仓库验证

对本地真实仓库执行：

```text
filemanagement_dfs_service
RepositoryScanner(platform="openharmony", skip_tests=True)
→ FunctionExtractor
→ OpenHarmonyIDLParser.collect
→ OpenHarmonyIPCResolver
```

结果：

| 项目 | 数量 |
|---|---:|
| production C/C++ 文件 | 570 |
| native 函数 | 4,205 |
| IDL 文件 | 2 |
| IDL interface | 2 |
| IDL methods | 73 |
| 图节点 | 75 |
| 图边 | 73（全部为 `interface_to_transaction`） |
| orphan | 73（全部为 `unresolved_ipc_stub`） |

这两个 IDL 的生成 native stub/transaction dispatch 不在 production 解析范围内，因此 resolver 没有凭名称猜测 handler，而是将 73 个缺口逐项保留。将测试目录纳入扫描后仍未生成伪造边；当前测试 stub 的 `OnRemoteRequest` 也没有实际 dispatch 语句。这验证了“缺失生成代码可审计、不会静默变成错误边”的行为。

## 6. 结论与边界

OH-14A-2 已完成 IPC resolver 的第一版确定性骨架，能够在存在明确 transaction/handler 证据时生成跨 IPC 语义边，并保留无法解析的覆盖缺口。

当前尚未处理：Proxy `SendRequest` 与 transaction code 的双向关联、IDL 生成文件缺失时的跨文件宏/枚举推理、SA profile 到接口的关联，以及 scanner/reachability 接入。这些应在后续小阶段逐项实现。
