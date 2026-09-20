# OH-14A-1：语义覆盖图容器契约

日期：2026-08-22  
阶段：OH-14A-1  
范围：建立 OpenHarmony 语义覆盖图的确定性容器；本阶段不接入 scanner/reachability，不实现 IPC resolver。

## 1. 原逻辑与修改逻辑

原逻辑已经有 `SemanticNode` 和 `SemanticEdge` 数据类，但没有统一的图容器：

- IDL、SA profile 和 C/C++ 语言调用图各自独立；
- 边的端点、置信度、证据和 resolver 版本没有集中校验；
- 相同关系可能重复写入；
- 无法解析的 IPC 关系容易被静默丢弃；
- 序列化顺序不固定，不利于审计、diff 和缓存哈希。

本阶段新增 `SemanticGraph`：

1. 统一管理节点、边和 `orphans`（未解析关系）；
2. 校验 schema version、非空 ID/类型、边端点、置信度和 resolver version；
3. 相同 `source_id + target_id + kind` 的边自动合并，保留全部独立证据并取最高置信度；
4. 未解析关系显式保存为 orphan，不伪造边也不静默删除；
5. 节点、边、orphan 以稳定顺序序列化，并支持 JSON round-trip。

## 2. 修改文件

- `libs/vulnfounder-core/core/platforms/graph.py`
  - 新增 `SemanticGraph`、证据合并、确定性序列化和反序列化逻辑。
- `libs/vulnfounder-core/tests/platforms/test_semantic_graph.py`
  - 覆盖重复边合并、证据保留、orphan、round-trip、悬空端点和非法置信度。

本阶段没有修改 generic scanner、C/C++ 调用图、入口检测器或 reachability 过滤逻辑。

## 3. 测试结果

阶段级测试：

```text
../../.venv/bin/python -m pytest \
  tests/platforms/test_semantic_graph.py tests/platforms/test_base.py -q
16 passed in 0.03s
```

平台相关回归：

```text
../../.venv/bin/python -m pytest tests/platforms tests/openharmony -q
72 passed, 6 skipped in 0.09s
```

另外执行了：

```text
../../.venv/bin/python -m py_compile \
  core/platforms/graph.py tests/platforms/test_semantic_graph.py
git diff --check
```

两项均通过。

## 4. 验证样例

阶段测试构造以下关系：

```text
function:service.cpp:HealthServiceStub::OnRemoteRequest
    ──stub_to_transaction──>
idl:transaction:OHOS.Health.IService:Enable
```

同一条边分别由 `CMD_ENABLE` 和方法名证据支持时，图中仍只有一条边，但两个证据都被保留，置信度取较高值。缺失 native handler 的 IDL 方法写入 `unresolved_ipc_method` orphan，后续 resolver 可以据此报告覆盖缺口。

## 5. 结论与边界

OH-14A-1 已完成语义覆盖图的基础契约，且没有改变现有入口检测和 reachable 结果。下一小阶段可在该容器上实现 OpenHarmony IPC resolver：从 IDL 方法、transaction 表项和 `OnRemoteRequest`/handler 函数证据生成实际 IPC 边，并把孤儿关系纳入覆盖报告。
