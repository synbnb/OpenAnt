# OH-SL-23：失败后远程版本选择与 Web 重试

日期：2026-08-31

## 目标

把上一阶段生成的 `repository_version_candidates.json` 接入 Web 和 Python CLI。
当 Git 拉取或拉取后只读验证失败时，用户可以查看远程 branch/tag、commit 和
推荐标记，选择一个候选版本后重新执行拉取流程。

## 原项目逻辑

失败后 session 会停在 `VERSION_SELECTION_REQUIRED`，但没有可执行的版本选择
命令或 Web 操作。用户只能查看失败事件，无法安全地把候选 revision 送回拉取
阶段。

## 本阶段逻辑

1. 状态机新增 `select_version()`，只允许在 `VERSION_SELECTION_REQUIRED` 状态
   工作。
2. revision 必须同时存在于 session 摘要和 worker 生成的候选产物中，并通过
   branch/tag/ref/commit 格式校验；不接受自由输入、路径穿越或 `unknown`。
3. 只更新对应的 `resolved` Manifest 映射 revision，记录
   `user.version_selected` 事件，然后返回 `CLONE`。
4. Web 新增 `POST /source-locator/sessions/{id}/select-version`，使用与其他
   修改操作相同的同源和 CSRF 检查。
5. 源码定位页面在失败状态显示候选版本、远程引用、commit 和失败原因；用户
   点击“选择版本并重试拉取”后，会先登记选择，再推进一次 Git 拉取。
6. 已存在的源码目录仍然不会被覆盖。若备用版本与现有目录冲突，系统会再次
   生成候选/冲突信息并暂停，后续阶段再设计独立的安全尝试目录策略。
7. 等待版本选择时，通用“执行下一阶段”和“自动运行到暂停点”按钮会置灰，
   防止用户重复点击一个不会改变状态的动作；此时页面只保留候选版本选择和
   重试拉取操作。

## 自动化测试

### Python

命令：

```text
../../.venv/bin/pytest -q tests/source_locator
```

结果：`265 passed in 23.64s`

命令：

```text
../../.venv/bin/ruff check core/source_locator/state_machine.py openant/cli.py tests/source_locator/test_state_machine.py tests/source_locator/test_cli_bridge.py
```

结果：`All checks passed!`

新增覆盖：

- 状态机只接受候选 revision，并更新目标 resolved mapping；
- CLI 重新读取并校验候选产物后才允许选择；
- 选择成功后输出单一 JSON envelope，状态恢复为 `CLONE`；
- 非法 revision 被拒绝。

### Go/Web

命令：

```text
go test ./...
```

工作目录：`apps/vulnfounder-cli`

结果：通过；`internal/server`（含新增接口、CSRF、参数和模板测试）通过。

命令：

```text
go vet ./...
```

结果：通过。

命令：

```text
node -e 'const fs=require("fs");const s=fs.readFileSync("apps/vulnfounder-cli/ui/source-locator.html","utf8").split("<script>\n")[1].split("</script>")[0];new Function(s);console.log("source-locator JS syntax ok")'
```

结果：`source-locator JS syntax ok`

## 全量回归备注

仓库全量 Python 测试在既有的 `tests/test_call_graph_output.py` 处失败：测试
fixture 被扫描为 0 个 Python 文件，旧的 `parsers/python/parse_repository.py`
仍无条件读取不存在的 `standalone_functions` 统计字段（`KeyError`）。该失败
与本阶段 source-locator/CLI/Web 修改无关；本阶段专门测试集和 Go 全量测试均
通过。
