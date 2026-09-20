# OH-SL-18：Web 源码定位与 LLM 审计展示

日期：2026-08-29

## 1. 目标

让用户可以在 `/source-locator` 页面输入剩余 socket 目标，并实时查看定位过程、
LLM 结构化决策和 OpenGrok 工具执行结果，而不必打开终端或手工读取 JSON。

## 2. 本轮实现

- Python worker 在每个 LLM 语义轮次写入 `llm.search.round` 事件；
- 事件包含轮次、动作类型、检索词或源码路径、预期关系、决策摘要、工具参数、
  返回摘要、证据 ID、上下文规模和剩余预算；
- 搜索结果在事件中只保留有界的文件路径、命中数量和短源码行，完整结果仍保存在
  `llm_search.json`、`search_plan.json` 和 `evidence.json`；
- Web 页面新增“LLM 语义检索审计”面板，通过 SSE 实时显示每轮动作，并在阶段完成
  后从 `llm_search.json` 恢复完整的有界审计；
- Web 的“启用 LLM 语义检索”开关已接到后端 `advance` 接口；模型配置名只允许字母、
  数字、点、下划线和连字符，并以独立参数传给 Python CLI。页面默认配置名为
  `openharmony-live-gpt`，最多 10 轮；关闭开关时保持确定性检索。
- 页面明确说明不展示模型隐藏思维链和完整提示词，只展示可复核的结构化决策摘要。

## 3. 验证结果

- `tests/source_locator`：**240 passed in 22.90s**；
- `ruff check core/source_locator tests/source_locator openant/cli.py`：**All checks passed**；
- `node --check`：`source-locator.html` 内嵌脚本通过；
- `go test ./internal/server ./internal/python`：**通过**；新增测试覆盖 LLM 参数传递、
  CSRF 保护和不安全模型配置名拒绝；
- `go test ./...`：**通过**（全部 Go 包）；
- 使用项目自带 Go 1.25.7 构建 `apps/vulnfounder-cli/bin/openant`，并在
  `127.0.0.1:18080` 启动 Web；首页和 `/source-locator` 均返回 HTTP 200，页面包含
  `llm-search`、`llm-config`、`llm.search.round` 和隐藏思维链边界提示。

## 4. 使用边界

源码层面的 Web 功能已经具备：

1. 访问 `/source-locator`；
2. 输入例如 `/dev/unix/socket/dnsproxyd`；
3. 点击“连续运行至暂停”；
4. 在实时事件和 LLM 审计面板查看每一轮动作；
5. 在“阶段产物”中查看 `llm_search.json`、`evidence.json`、`verification.json` 等完整文件。

当前二进制已经重新构建并启动。可直接访问：

```bash
http://127.0.0.1:18080/source-locator
```

操作时输入 socket（例如 `/dev/unix/socket/dnsproxyd`），保持“启用 LLM 语义检索”勾选，
点击“连续运行至暂停”。若只想复现确定性基线，可取消勾选；同一会话后续推进请求会
继续携带当前开关和配置名。

## 5. 界面可读性补充

- 目标版本输入列宽调整为 260 至 280 像素，并将提示改为“默认：OpenHarmony-6.1-LTS”
  （留空仍使用配置默认版本）；
- “推进一个阶段”改为“执行下一阶段”，表示只执行一个状态转换；
- “连续运行至暂停”改为“自动运行到暂停点”，并在按钮下方说明会连续执行到用户确认、
  流程终态或错误（单次最多 16 个状态，未暂停时可再次点击）；
- 页面明确显示“默认：OpenHarmony-6.1-LTS”版本提示，但留空仍由配置文件决定实际版本。
- 执行按钮增加即时“执行中…”状态、旋转提示、`aria-busy` 标记和重复点击保护；失败时
  直接在页面通知区显示错误。

## 6. 本轮卡顿问题定位与修复

### 现象

页面在“正在执行定位阶段，请稍候”处长时间不刷新，用户看不到已经产生的事件。

### 实际原因

前端 `loadEvents()` 原先用普通 `fetch()` 请求 `/events` 并等待 JSON；但该地址是
长期保持连接的 SSE 实时事件流，非终态 session 不会结束响应。因此推进请求在等待
事件接口返回时一直保持 pending，页面看起来像卡住。期间后端 Python worker 可能只是在
等待模型或 OpenGrok 的 HTTPS 响应，并非进程崩溃。

### 修复

- 新增 `GET /source-locator/sessions/{id}/events/snapshot`，返回有限的 JSON 事件历史，
  供页面刷新、推进完成后的状态同步和审计面板加载；
- `/events` 继续只由 `EventSource` 使用，负责实时推送和断线重放；
- 增加 Go 回归测试，验证快照响应是合法 JSON、包含事件列表和 `last_seq`，并保留原有
  SSE 测试；
- 全量重建并重启 Web 后，用实际会话 `loc_zrzMGsenyB2Vwh0S` 验证：
  `GET .../events/snapshot` 在约束时间内返回 HTTP 200，包含 15 条事件，`last_seq=15`；
  session 状态为 `PARTIAL`，说明定位 worker 已结束并写出产物。

### 修复后验证

- `go test ./...`：**通过**；
- `node --check`（内嵌页面脚本）：**通过**；
- Web 首页与 `/source-locator`：HTTP 200；
- SSE 实时端点仍返回 `text/event-stream`，首批事件可正常重放。

## 7. 本轮“补证不烂尾”修复与真实复测

### 修复内容

- `VERIFY_EVIDENCE` 不再把一次缺失谓词直接变成终态 `PARTIAL`。在启用语义规划器且预算允许时，先进入 `RECOVER_EVIDENCE`，把缺失谓词、候选源码路径和上一次重复动作反馈写入模型上下文；补证后回到 `TRACE_EVIDENCE`，重新经过源码读取、归因和 Manifest 排序。
- 恢复触发的硬门与方案一致，只针对 `socket_identity`、`socket_acquire_or_bind`、`server_consumer`、`manifest_mapping`；`service_relation`、`protocol_dispatch` 仍会在归因结果中展示，但不会因为单独缺失阻塞确认。
- 模型提出重复动作时不再立即停止。重复调用消耗模型调用预算但不消耗“有效动作”预算，worker 把拒绝的动作 key 和中文反馈传给下一轮；连续三次重复才结束本轮，且仍保留 `llm_search.json` 和事件记录。
- 服务端注册识别改为通用数据流形状（例如 `info.server = PIPE_NAME`、`CreateSocketListener(...)`），排除 `NULL/nullptr/0` 空初始化，不绑定某一个仓库 API。
- 仓库排序不再按原始命中数量。映射先聚合同一 Manifest 项目下的跨文件证据，再按目标 socket 的身份锚点、服务端注册/获取 fd、消费和协议分派角色加权；只有通用 `SocketServer` 或 `ParamService` 名称而没有目标身份的仓库会被保留为低优先级候选。

### 离线测试

- `tests/source_locator`：**247 passed**；包含恢复状态转换、缺失 `socket_acquire_or_bind` 的 LLM 补证闭环、“重复后选择新动作”和“同一检索词不同语义动作”测试。
- `py_compile`：`worker.py`、`llm_search_planner.py`、`state_machine.py` 通过。
- Go：`apps/vulnfounder-cli` 执行 `go test ./...`，**全部通过**。
- 页面脚本：`node --check` 通过。

### 真实 OpenGrok 复测

目标：`/dev/unix/socket/paramservice`，版本：`OpenHarmony-6.1-LTS`。

- 带 LLM 的真实 session `loc_realparam20260829`：OpenGrok 和模型检索实际完成 10 轮，最终到达等待用户确认；未触发恢复是因为注册证据已在初次追踪阶段找到。
- 无 LLM 的真实 session `loc_realparamfinal`：最终状态 `AWAIT_USER_CONFIRMATION`；主映射为 `startup_init`。
- 主映射证据包含真实源码行：`base/startup/init/services/param/linux/param_service.c:441` 的 `info.server = PIPE_NAME`、`:445` 的 `ParamServerCreate`，以及 `param_request.c:76` 的 `switch`、`:101` 的 `recv`。
- 新排序产物中 `startup_init` 的目标身份锚点和服务端角色分数高于 `filemanagement_dfs_service`、内核和第三方候选；后者的命中主要是 `ParamService` 变量或通用 `switch`，不会再被选为主仓库。

### 结论

本轮修复同时保留两道边界：模型只能提出有证据引用的检索动作，安全谓词仍由确定性源码分类计算；但缺证时会继续有界探索，不会因为一次重复动作或单个规则未命中就直接烂尾。全量 Python 套件未作为本轮验收门槛（该仓库共有 9422 项，包含与 source-locator 无关的动态/工具链 fixture）；source-locator、Go Web 和真实 OpenGrok 验收均通过。

## 8. 读文件动作的追踪闭环补强（2026-08-29）

补充检查发现：LLM 选择 `read_file` 时，源码行已经进入 `evidence.json`，但如果不把
该文件路径交给下一次 `TRACE_EVIDENCE`，后续阶段可能只读取初始搜索响应中的路径。
现已把读文件动作转换成有界的搜索计划执行记录，仅保留已选中的源码行，不保存完整源码；
因此 `search_*` 和 `read_file` 两类模型动作都能进入同一条“写证据 → 追踪 → 归因”闭环。

验证结果：`tests/source_locator/test_worker.py` **14 passed**；全套
`tests/source_locator` **247 passed**；读文件回归明确检查 `search_plan.json` 中包含该文件的
有界执行记录。该改动不放宽模型权限，也不改变仓库确认门禁。

## 9. 确认前仓库与证据可视化（2026-08-29）

### 用户问题

原确认区只显示“需要你的确认”，用户必须翻阅日志或多个 JSON 产物，才能知道将拉取
哪个仓库以及哪些源码证据支撑这个候选。

### 实现

- `VERIFY_EVIDENCE` 现在生成有界的 `confirmation_summary.json`，由已校验的
  `RepositoryMapping`、服务端/客户端归因和 `EvidenceStore` 生成，不接受模型自由文本
  作为仓库或证据结论。
- 摘要直接包含目标、GitCode 地址、项目名、版本、预计落盘位置、源码根目录、命中路径、
  映射分数、服务端强制条件、角色候选、关键源码位置和源码片段；完整证据仍保留在
  `evidence.json`，原始 `verification.json` 继续可查看。
- Web 确认区改为响应式摘要卡：仓库信息、服务端判定、客户端通信线索和关键证据分栏展示，
  角色显示源码位置与依据，证据显示中文类型、文件行号和片段；页面使用 `textContent`
  渲染不可信源码内容，避免把源码当作 HTML。
- 对于改造前已经处于确认状态的历史会话，前端在缺少摘要产物时兼容读取
  `verification.json` 与 `evidence.json`，生成临时摘要，不改写历史文件。
- 中英文界面均增加摘要字段翻译和谓词说明；小屏幕下卡片自动改为单列。

### 单独验证

- `tests/source_locator/test_worker.py`：**14 passed**；检查确认摘要存在、主仓库为
  `startup_init`、GitCode 地址和 `source_code_base/startup_init` 落盘位置正确，并且摘要
  证据包含源码路径与片段。
- `tests/source_locator`：**247 passed**。
- `ruff check core/source_locator tests/source_locator`：**通过**。
- `node --check`（内嵌 source-locator 页面脚本）：**通过**。
- `go test ./...`（`apps/vulnfounder-cli`）：**全部通过**。
- 重建并重启 Web 后，`GET /source-locator` 返回 **HTTP 200**，页面包含确认摘要卡；实际
  历史会话 `loc_JdYWaUhbGqAtc7B7` 的 `verification.json`、`evidence.json` 返回 **200**，
  新摘要文件按预期返回 **404**，可验证前端兼容分支会被使用。
- 使用实际历史会话数据执行前端兼容函数 smoke：成功得到 `startup_init`、
  `https://gitcode.com/openharmony/startup_init`、`source_code_base/startup_init`，
  展示 12 条关键证据（总计 350 条）。

### 使用效果

当会话进入“等待用户确认”时，用户无需离开当前页面即可看到“将拉取的仓库”和“关键源码
证据”。确认按钮仍然是唯一触发 Git 拉取的入口，摘要展示不会放宽仓库策略或安全门禁。

## 10. 定位会话删除（2026-08-29）

### 实现内容

- Python `LocatorSessionStore.delete(session_id)` 只删除经过 ID 校验的单个
  `source-locator/<session_id>` 目录及其阶段产物；拒绝符号链接和越界路径。
- CLI 增加 `source-locator delete <session_id> --root <root>`，保持与 Web
  桥接一致的单 JSON 响应；删除说明明确表示不会触碰 `source_code_base` 中的源码仓库。
- Go Web 增加 `DELETE /source-locator/sessions/{id}`，复用 loopback、CSRF、路径和
  session 存在性校验；所有 session 写操作共用互斥锁，避免删除与推进/取消/拒绝并发写盘。
- Web 左侧每个历史会话增加“删除会话”按钮，状态工具栏也提供当前会话删除入口。
  删除前显示不可恢复确认，成功后关闭 SSE、清空当前详情并刷新历史列表；删除进行中
  暂停其它推进操作。确认文案强调只删除定位产物，不删除已经拉取的源码。
- 删除按钮使用独立布局、键盘焦点样式和窄屏响应式规则，不把会话字段拼接进 HTML。

### 单独测试

- `tests/source_locator`：**249 passed**，覆盖存储层“只删一个、保留其它 session”、
  CLI 删除后的 JSON 信封和目录消失。
- `ruff check core/source_locator tests/source_locator openant/cli.py`：**通过**。
- 内嵌 `source-locator.html` 提取后执行 `node --check`：**通过**。
- `apps/vulnfounder-cli` 执行 `go test ./...`：**全部通过**，包含 CSRF 拒绝、合法删除请求
  以及传递 `source-locator delete` 参数的 HTTP 回归测试。

### 删除边界

本功能删除的是 Web 输出目录下的定位 session（事件、证据、检索和确认产物）。它不会
删除 `source_code_base` 中已经由确认流程拉取的仓库；若用户需要删除源码仓库，仍须在
源码目录管理流程中单独操作。

## 11. GitCode 重定向兼容修复（2026-08-29）

### 现象与根因

确认 `/dev/unix/socket/paramservice` 后，拉取 `startup_init` 在第一条 `git clone`
命令失败，日志为 HTTP 301。Manifest 生成的逻辑仓库地址是
`https://gitcode.com/openharmony/startup_init`；GitCode 的 smart-HTTP 端点会把该地址
重定向到带尾斜杠的 URL，而仓库管理器为防止未经校验的跨站跳转，固定设置了
`http.followRedirects=false`，所以 Git 在初始化阶段直接退出。分支
`OpenHarmony-6.1-LTS` 存在，网络和权限均不是原因。

### 修复

- 新增 Git 传输地址规范化：仅当已通过 GitCode allowlist 的主机为 `gitcode.com` 且逻辑
  地址没有后缀时，实际 clone 地址补为 `https://.../<repo>.git`。
- 策略校验、用户确认、证据摘要和交接产物仍使用无后缀的逻辑 canonical URL；不放宽
  重定向开关，也不接受模型提供的 URL。
- 非 GitCode 配置主机不自动追加后缀，避免改变自定义 Git 服务行为。

### 验证

- 在相同的 `http.followRedirects=false` 配置下，实际测试无后缀地址仍稳定复现 301；
  带 `.git` 的地址 `git clone --depth 1 --no-tags --no-checkout` 成功创建 Git 工作树。
- 使用项目自身 `RepositoryManager` 在临时项目根目录执行完整确认后拉取，结果为
  `status=cloned`，实际 clone 参数包含
  `https://gitcode.com/openharmony/startup_init.git`，并成功解析到
  `OpenHarmony-6.1-LTS` commit `be5b8494c1d60ebc239f673e6296422376a65b38`。
- `tests/source_locator/test_repository_manager.py`：**15 passed**，回归断言 clone
  使用 `.git` 传输地址且原有 Git 安全参数保持不变。
- 全套 `tests/source_locator`：**249 passed**；Ruff 检查通过。
- `apps/vulnfounder-cli`：`go test ./...` 全部通过；重建并重启 Web 后
  `GET /source-locator` 返回 HTTP 200。

## 12. 初始检索可视化面板（2026-08-29）

### 实现内容

- 在定位页面的实时事件和阶段产物下方增加“初始检索可视化”面板。检索进行中通过 SSE
  事件实时显示最近一轮动作、目标、返回状态、命中数量和检索目的；阶段产物生成后自动
  读取 `search_plan.json`，并兼容只有 `llm_search.json` 的历史会话。
- 将查询动作、成功次数、候选文件、源码证据、关系边和模型轮次渲染为中文指标卡；不把
  JSON 直接塞进展示区。完整原始 JSON 仍可从“阶段产物”打开，便于审计和复核。
- 用 SVG 绘制证据关系图：节点可点击或用键盘 Enter/空格选择，显示关联关系；提供缩小、
  适应和放大按钮。证据列表显示中文证据类型、文件位置、符号和源码片段，支持按文件、
  符号或片段筛选，并与图节点联动。
- 为避免大仓库结果阻塞浏览器，图最多绘制 100 个节点和 180 条边，证据列表最多展示
  120 条；面板同时显示实际总数，完整数据不被修改。源码和模型输出均通过 `textContent`
  写入 DOM，不执行不可信 HTML。
- 在删除、切换和新建会话时清空可视化状态；中英文切换、空状态、加载状态和窄屏布局均
  有对应处理。

### 单独测试

- 内嵌 `source-locator.html` 脚本执行 `node --check`：**通过**。
- `apps/vulnfounder-cli` 执行 `go test ./...`：**全部通过**；模板测试增加了可视化面板、
  图交互、筛选器和产物读取标记断言。
- `tests/source_locator`：**249 passed**。
- 重建并重启 Web 后，`GET /source-locator` 返回 **HTTP 200**；真实历史会话
  `loc_tdppVCue8RFChe_h` 的 `evidence.json` 返回 **200**，包含 488 条证据和 109 条关系边。
- 使用实际 Chrome 无头浏览器加载页面并选择该历史会话：面板显示 **10 次查询、10 次成功、
  39 个候选文件、488 条证据、109 条关系边、10 个模型轮次**，实际绘制 100 个节点和 99 条
  可见边；证据列表展示 120 条。
- 浏览器交互 smoke：点击图节点后出现选中状态和关联关系；输入 `param_utils.h` 后筛选为
  **6 条**，页眉显示“显示 6/488 条”。
