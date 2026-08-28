# OH-SL-00A：OpenGrok 实例能力快照与离线回放测试记录

日期：2026-08-28
阶段：源码定位器 SL-00A（能力基线冻结）
目标：把已实际访问过的 OpenGrok 1.14.11 实例能力保存为小型脱敏夹具，并用离线回放验证客户端对真实响应形态的处理。

## 1. 本阶段原有逻辑与本阶段变更

原有定位器客户端直接访问 OpenGrok HTTP 接口。它可以探测实例、搜索符号、读取源码，并在文件内容接口需要认证时回退到 raw 源码接口；但是此前没有固定的真实响应样本，后续修改容易只对理想化 Mock 响应有效。

本阶段没有修改生产代码，也没有改变扫描流程。新增一组来自实际实例的脱敏回放数据和契约测试：

- `capability_snapshot.json`：保存根页面、ping、索引时间、建议配置、搜索探测、文件内容、raw、xref 的状态码、内容类型和能力结果。
- `search_init_param_service.json`：保存对 `InitParamService` 的实际搜索结果，包含 liteos/linux 两个文件和命中行信息。
- `raw_param_service_excerpt.c`：只保留与 `param_service.c` 定位证据相关的源码片段，不保存完整仓库源码。
- `test_opengrok_live_fixture_contract.py`：使用 `httpx.MockTransport` 在本地回放上述响应，覆盖探测、搜索、文件内容 401、raw 回退和证据读取。

因此，本阶段的逻辑链为：

`真实 OpenGrok 响应 → 去除认证与无关内容 → 固定小型夹具 → 离线回放生产客户端 → 断言能力和关键证据`

## 2. 实际实例与关键观察

测试样本来自 OpenHarmony OpenGrok 实例：

- 实例版本：OpenGrok 1.14.11，构建版本 `512e738c...`
- 索引时间：`2026-04-09T10:21:31.737+00:00`
- 项目：`openharmony`
- 搜索接口：HTTP 200，可返回结构化结果
- `api/v1/file/content`：HTTP 401，需要认证
- `raw`：HTTP 200，可作为源码读取回退
- `xref`：HTTP 200，可访问交叉引用页面

真实搜索结果确认 `InitParamService` 在以下两个文件中出现：

`base/startup/init/services/param/liteos/param_service.c` 与
`base/startup/init/services/param/linux/param_service.c`。

回放的 Linux 片段还确认了 `OnIncomingConnect`、`PIPE_NAME`、`info.server` 和 `info.incomingConnect` 等定位证据可被客户端保留。

## 3. 脱敏与安全边界

夹具已移除 Cookie、`Set-Cookie`、Authorization 头和认证失败响应体；raw 源码仅保留任务相关片段。测试同时检查夹具中不存在 `set-cookie:`、`jsessionid=`、`authorization:`、`bearer `、`api_key` 等凭据痕迹，并限制单文件小于 16 KiB、总大小小于 24 KiB。

这组文件是测试数据，不代表生产环境可以绕过 OpenGrok 认证，也不把认证信息写入仓库。

## 4. 独立测试

在 `OpenAnt` 虚拟环境中执行：

```text
cd libs/openant-core
../../.venv/bin/python -m pytest -q \
  tests/source_locator/test_opengrok_live_fixture_contract.py \
  tests/test_opengrok_client.py \
  tests/test_opengrok_protocol_models.py
```

结果：`30 passed in 0.04s`。

静态检查：

```text
.venv/bin/ruff check \
  libs/openant-core/tests/source_locator/test_opengrok_live_fixture_contract.py
```

结果：`All checks passed!`。

补丁空白检查 `git diff --check` 通过。

## 5. 结论与边界

本阶段证明当前客户端能够处理真实实例的“搜索可用、文件内容接口需认证、raw 可回退”这一关键组合，并能保留目标服务的搜索和源码证据。它还没有实现代码仓库映射、GitCode URL 推断、仓库克隆或对话式确认；这些属于后续阶段，不能由本阶段测试结果推断已经完成。

下一阶段建议先把实例能力快照接入配置与启动探测，再实现搜索结果到 OpenHarmony 仓库的证据化映射。
