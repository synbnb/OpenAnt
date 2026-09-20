# Agentic 上下文图 Web 改造测试记录

## 测试目标

确认 `dataset_enhanced.json` 可以在独立产物查看器中进入 Agentic 上下文图视图，并区分原生调用边与模型选入的上下文关联。

## 本阶段修改

- 在 `artifact-view.html` 中为 `dataset_enhanced.json` 增加图查看入口。
- 图视图同时读取原生 `call_graph.json` 和增强数据集中的 `agent_context.include_functions`。
- 原生解析调用边使用实线和箭头；Agentic 上下文关联使用橙色虚线，不标记为已经证明的调用方向。
- 节点详情保留原生直接调用者/被调用者，并增加 Agentic 上下文关联字段。
- 保留原始调用图和原始 JSON，不覆盖或改写原始产物。

## 自动检查

### 1. 内联 JavaScript 语法检查

执行：

```text
node -e '读取 artifact-view.html 的 script 并交给 new Function 校验'
```

结果：通过（`artifact-view inline JavaScript syntax: OK`）。

### 2. 真实增强产物检查

检查文件：

```text
/Users/shiyu/.openant/webui/ecad4bdd3d5f9ae8/dataset_enhanced.json
```

结果：

- 增强单元：93 个。
- Agentic 上下文关联：258 条（按“来源单元 → 模型选入函数”去重后为 258 条；页面额外按无向节点对合并重复显示的虚线）。
- 其中 6 个模型选入的函数标识没有对应的原生函数索引记录；页面会保留为“仅有 Agentic 标识”的占位节点，并在工具栏显示未解析数量，不会静默丢弃。
- 已确认存在可用于展示的真实关联，例如 `MedicalSensorServiceStub` 到多个 `OnRemoteRequest`/内部处理函数的关联。

### 3. 差异和格式检查

执行 `git diff --check`，结果通过，无空白错误。

### 4. Go 服务端测试

未能在当前执行环境运行 `go test ./apps/vulnfounder-cli/internal/server`：当前环境没有安装 `go` 命令（`command not found: go`）。该测试需要在安装 Go 的开发环境中补跑。

## 使用方式

1. 重新编译或重启包含最新嵌入页面的 Web 程序。
2. 打开某次扫描的 `dataset_enhanced.json` 产物。
3. 点击右上角“Agentic 上下文图”。
4. 选择入口函数，使用“查看层数”或展开/收起按钮浏览图。
5. 通过图例区分：实线为原生调用边，橙色虚线为模型选入的上下文关联。

## 结论

前端逻辑和真实增强数据兼容，旧的原生调用图查看逻辑保持不变。由于当前环境缺少 Go，服务端模板测试尚未执行。
