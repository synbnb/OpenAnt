# OH-18B：真实 OpenHarmony semantic IPC 边覆盖审计

日期：2026-08-22  
阶段：OH-18B 真实正常服务仓库覆盖验收  
状态：通过（未触发 resolver 修改）

## 1. 审计目的

OH-18A 已将 semantic graph 以“只增不减”的方式接入 reachable。本阶段不改
生产代码，验证真实正常服务仓库是否能够产出有效的：

- `stub_to_transaction`；
- `transaction_to_handler`；
- `proxy_to_transaction`；
- semantic overlay 是否真的新增 reachable 单元；
- native reachable 是否始终保持不变。

如果发现 semantic graph 中已有明确 native 证据但没有生成关系，才进入 resolver
修复子阶段。本次结果没有满足这一条件。

## 2. 统一运行方式

三个仓库均执行：

```text
./.venv/bin/python libs/vulnfounder-core/parsers/c/test_pipeline.py <repo> \
  --output <tmp-output> --processing-level reachable \
  --platform openharmony --skip-tests
```

过滤器的 `reachability_filter` 元数据同时记录：
`native_reachable_units`、`semantic_reachable_added`、
`semantic_overlay.candidate_edges`、`edges_added`、`ignored_edge_count` 和
`monotonicity_violation`。

## 3. 结果汇总

| 仓库 | C/C++ 文件 | Units | 入口点 | native reachable | 最终 reachable | semantic graph | semantic 新增 |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| `systemabilitymgr_samgr` | 97 | 1136 | 31 | 91 | 91 | 无 | 0 |
| `communication_ipc` | 251 | 2604 | 12 | 86 | 86 | 无 | 0 |
| `window_window_manager` | 1089 | 23875 | 52 | 2647 | 2647 | 有 | 0 |

三个仓库的 `monotonicity_violation` 均为 `false`。

## 4. `window_window_manager` 详细结果

输出目录：

```text
/private/tmp/openant-oh18b-window-reachable
```

解析结果：

- 1089 个 C/C++ 文件；
- 24033 个函数；
- 33862 条 native 调用图边；
- 23875 个 Units；
- reachable 过滤后 2647 个 Units，裁剪 88.9%。

semantic graph：

| 边类型 | 数量 |
| --- | ---: |
| `interface_to_transaction` | 87 |
| `stub_to_transaction` | 3 |
| `transaction_to_handler` | 3 |
| `proxy_to_transaction` | 1 |
| 合计 | 94 |

三条完整的 stub→transaction→handler 路径为：

```text
ScreenSessionManagerLiteStub::OnRemoteRequest
  -> GetCutoutInfo
  -> HandleGetCutoutInfo

ScreenSessionManagerLiteStub::OnRemoteRequest
  -> GetDefaultDisplayInfo
  -> HandleGetDefaultDisplayInfo

ScreenSessionManagerLiteStub::OnRemoteRequest
  -> RegisterDisplayManagerAgent
  -> HandleRegisterDisplayManagerAgent
```

三条折叠后的 semantic native 边在原生调用图中均已存在。因此：

```text
candidate_edges = 3
edges_added = 0
native_reachable_units = 2647
semantic_reachable_added = 0
monotonicity_violation = false
```

这说明本次 overlay 接入没有失效，而是确认了该仓库的三条已解析 IPC handler
路径并未被 native reachable 漏掉。

## 5. 未解析项归因

该仓库 semantic graph 另有 169 个 orphan：

- `unresolved_ipc_stub`：84；
- `unresolved_ipc_proxy`：45；
- `ambiguous_ipc_proxy`：40。

这些记录已经被显式写入 `semantic_graph.json`，原因分别是“没有匹配的 native
dispatch 证据”“没有匹配的 `SendRequest` 证据”或“多个 native proxy 候选”。
它们不能直接证明 resolver 漏边：可能是生成代码不在当前仓库、实现位于其他
组件、测试/构建条件未纳入，或确实需要更强的匹配规则。因此本阶段不把它们
强行转成低置信度 reachable 边，避免扩大攻击面范围。

## 6. 结论与下一阶段建议

OH-18A 的 semantic reachable 接入已通过真实仓库验收：

1. 有 IDL 和完整 native stub/handler 的路径可以被解析；
2. 已经存在于 native 图的路径不会被重复扩大；
3. 没有 semantic graph 的仓库安全回退 native 逻辑；
4. 接入不会缩小原有 reachable 范围。

下一阶段可以进入 **OH-20 规则 schema/加载器**。如果希望继续提高真实 IPC
覆盖率，则应另立 resolver 增强任务，针对上述 unresolved/ambiguous 项逐项选择
有完整源码证据的样本，先建立正反测试，再扩展匹配规则。

