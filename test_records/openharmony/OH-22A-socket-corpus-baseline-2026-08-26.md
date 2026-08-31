# OH-22A Socket 验收语料基线测试记录

- 日期：2026-08-26
- 项目：OpenAnt
- 平台：OpenHarmony
- 数据集：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code`
- 测试状态：**静态前端全量完成；LLM 漏洞判定未执行**
- 产物目录：`debug_outputs/OH-22A-socket-corpus/`

## 1. 测试目的

在不产生大模型 API 费用的前提下，对验收数据集中的全部 9 个仓库运行当前 OpenHarmony C/C++ 静态前端，检查：

1. 生产源码能否被扫描和 tree-sitter 解析；
2. 原生调用图能否建立；
3. 当前入口检测与 reachable 过滤能否覆盖直接读取 socket 数据的函数；
4. OH-22A 残余调用诊断在真实网络仓库上的有效性；
5. 大型仓库的时间和磁盘开销；
6. 下一阶段优化是否具有跨仓库价值，而不是只修复单个样例。

本轮没有运行 Detect/Analyze/Verify 的真实 LLM 漏洞分析。静态前端共生成 54,406 个 Unit，直接对全部 Unit 调用模型会产生显著费用，且本轮目标是先定位前端覆盖缺口。

## 2. 输入版本

| 仓库 | Git commit |
|---|---|
| communication_netmanager_base | `3b4d31a7e55af2cf65dfd4089a2199c98012f620` |
| developtools_hdc | `f2e361642669675de725afb878449103ee4e38ca` |
| hiviewdfx_faultloggerd | `08916c9e3230c77b492ef75e49d59d480eaf75d8` |
| hiviewdfx_hilog | `386378306e6d4a6e7733db59d4faa3c4f590137f` |
| hiviewdfx_hiview | `84c78fb4af9d85477fdce229c230f03075f7ede1` |
| multimedia_audio_framework | `680ea14e108abe6b8617fd8c55e435871c222920` |
| startup_appspawn | `d4994311e94fc401dc4629c3f4211f823d403ad3` |
| startup_init | `e5bebff39ae16c3c610d6021a8a7e85590c7b57b` |
| telephony_core_service | `ff841ac9ed2d52576a8e254536dea3ecee21e1ff` |

## 3. 执行方式

每个仓库使用相同命令，`<repo>` 和 `<name>` 分别替换为仓库绝对路径和仓库名：

```bash
./.venv/bin/python libs/openant-core/parsers/c/test_pipeline.py \
  <repo> \
  --output debug_outputs/OH-22A-socket-corpus/<name> \
  --platform openharmony \
  --processing-level all \
  --skip-tests
```

配置含义：

- `--platform openharmony`：启用 OpenHarmony 文件范围、平台入口和语义图逻辑；
- `--processing-level all`：生成全部已解析 C/C++ 函数的 Unit，用于观察完整静态前端结果；
- `--skip-tests`：本轮分析生产源码，过滤测试目录；
- 未传入 LLM 配置，不调用任何外部模型。

## 4. 解析与调用图结果

| 仓库 | 解析文件 | 函数/Unit | 原生调用边 | 孤立函数 | 总耗时 | 输出大小 |
|---|---:|---:|---:|---:|---:|---:|
| communication_netmanager_base | 730 | 7,563 | 6,394 | 2,655 | 47.92 s | 87 MB |
| developtools_hdc | 196 | 2,052 | 2,831 | 381 | 6.10 s | 37 MB |
| hiviewdfx_faultloggerd | 359 | 2,994 | 3,415 | 803 | 11.59 s | 32 MB |
| hiviewdfx_hilog | 117 | 857 | 851 | 207 | 1.00 s | 8.4 MB |
| hiviewdfx_hiview | 1,054 | 7,008 | 5,687 | 2,600 | 100.13 s | 65 MB |
| multimedia_audio_framework | 1,514 | 23,178 | 33,816 | 5,823 | 332.44 s | 732 MB |
| startup_appspawn | 120 | 1,204 | 2,267 | 52 | 7.79 s | 25 MB |
| startup_init | 343 | 2,708 | 4,929 | 230 | 15.90 s | 43 MB |
| telephony_core_service | 540 | 6,842 | 7,196 | 2,181 | 43.53 s | 83 MB |
| **合计** | **4,973** | **54,406** | **67,386** | **14,932** | — | **约 1.1 GB** |

### 4.1 已确认事实

- 9/9 仓库执行成功，没有仓库级失败。
- 4,973 个符合当前 C/C++ 生产范围的文件全部进入解析，`eligible_files == parsed_files`。
- 发现文件共 11,384 个；生产范围之外还包括 2,349 个测试文件、742 个 fuzz 文件和 188 个当前语言前端不支持的文件。
- 不支持文件主要出现在包含 Rust、ETS/TS 绑定层的仓库。本记录只证明 C/C++ 前端覆盖，不代表这些语言已覆盖。
- `multimedia_audio_framework/dataset.json` 为 622 MB，整个单仓产物为 732 MB，明显存在规模化开销问题。

### 4.2 性能归因抽测

将已保存的 `call_graph.json` 重新送入 OH-22A 诊断器：

| 仓库 | 全流程耗时 | OH-22A 诊断耗时 |
|---|---:|---:|
| communication_netmanager_base | 47.92 s | 1.93 s |
| multimedia_audio_framework | 332.44 s | 5.55 s |

因此，大仓库 332 秒的主要耗时不是 OH-22A 诊断器造成的。结合 622 MB 的 `dataset.json`，当前更可能的瓶颈是全部 Unit 的上下文展开和 JSON 序列化；这是源码结构和产物规模支持的推断，尚未通过逐阶段 profiler 定量确认。

## 5. Socket 入口与可达性审计

### 5.1 审计口径

从当前调用图函数源码中查找直接调用以下强 socket 接收原语的函数：

`accept`、`accept4`、`recv`、`recvfrom`、`recvmsg`、`recvmmsg`

这些函数作为“直接 socket 接收函数”抽样集合。该集合适合验证明显遗漏，但不是完整 socket 真值集：它不覆盖经项目封装函数、普通 `read()`、虚函数接口或跨语言边界间接读取的情况。

### 5.2 汇总结果

| 仓库 | 当前入口 | 当前可达函数 | 直接 socket 接收函数 | 被识别为入口 | 当前可达 | 遗漏 |
|---|---:|---:|---:|---:|---:|---:|
| communication_netmanager_base | 61 | 250 | 18 | 0 | 0 | 18 |
| developtools_hdc | 15 | 160 | 4 | 0 | 1 | 3 |
| hiviewdfx_faultloggerd | 17 | 72 | 4 | 0 | 0 | 4 |
| hiviewdfx_hilog | 18 | 75 | 4 | 0 | 0 | 4 |
| hiviewdfx_hiview | 67 | 197 | 1 | 0 | 0 | 1 |
| multimedia_audio_framework | 29 | 286 | 1 | 0 | 0 | 1 |
| startup_appspawn | 17 | 79 | 1 | 0 | 0 | 1 |
| startup_init | 41 | 615 | 7 | 0 | 2 | 5 |
| telephony_core_service | 50 | 113 | 0 | 0 | 0 | 0 |
| **合计** | **315** | **1,847** | **40** | **0** | **3** | **37** |

### 5.3 结论

这是本轮最重要的泛用性缺口：**当前 OpenHarmony 入口检测器没有 native socket 接收入口类型。**

当前平台检测器覆盖 Binder `OnRemoteRequest`、System Ability 生命周期、Ability 生命周期和 HDF 入口；通用输入规则覆盖 Web/CLI/文件等输入，但没有 C/C++ 的 `accept/recv/recvfrom/recvmsg`。因此 40 个直接接收函数没有任何一个被标记为入口，只有 3 个碰巧通过其他入口的原生调用边可达。

这会导致 reachable 模式在 socket 型仓库中大范围裁剪真正处理外部数据的函数。以 `communication_netmanager_base` 为例，18 个直接接收函数全部不可达，包括本地代理、DNS 代理、VPN Unix socket、fwmarkd、netlink 和 UDP/TCP 接收路径。

## 6. 调用图缺边审计

40 个直接 socket 接收函数中：

- 32 个在原生调用图中至少有一个调用者；
- 8 个没有原生调用者；
- 但最终仅 3 个能从现有入口到达。

这说明问题分为两层：

1. **主要问题是入口种子缺失。** 即使某个接收函数的内部调用边已经存在，没有从 socket 边界开始的入口，reachable 仍不会保留它。
2. **次要问题是回调/线程/事件循环边缺失。** 8 个接收函数完全没有调用者，源码中能看到它们通过函数指针、线程成员指针或事件监听器注册，而非普通直接调用。

真实源码例子：

- `ProxyServer::AcceptLoop` 通过 `std::thread(&ProxyServer::AcceptLoop, this)` 启动；
- `RunForClientFd` 作为参数传入 `FwmarkEpollServer(serverSockfd, RunForClientFd)`；
- `HandleRecvMessage` 通过 `info.handleRecvMsg = HandleRecvMessage` 注册，再交给事件循环；
- `SocketServerListener::OnEventPoll` 由 poll/event listener 框架回调。

这些都不是 tree-sitter “无法解析语法”。tree-sitter 能生成 AST；当前缺口发生在调用图构建后的语义关联阶段：构建器还没有把注册关系转换为调用边。

## 7. OH-22A 残余诊断效果

| 仓库 | 未解析间接调用点 | 分发表赋值 | 候选边 | 无候选调用点 |
|---|---:|---:|---:|---:|
| communication_netmanager_base | 16 | 220 | 74 | 1 |
| developtools_hdc | 0 | 0 | 0 | 0 |
| hiviewdfx_faultloggerd | 0 | 0 | 0 | 0 |
| hiviewdfx_hilog | 0 | 0 | 0 | 0 |
| hiviewdfx_hiview | 0 | 0 | 0 | 0 |
| multimedia_audio_framework | 53 | 33 | 0 | 53 |
| startup_appspawn | 1 | 0 | 0 | 1 |
| startup_init | 0 | 0 | 0 | 0 |
| telephony_core_service | 0 | 0 | 0 | 0 |
| **合计** | **70** | **253** | **74** | **55** |

### 7.1 有效部分

`communication_netmanager_base` 的 16 个间接成员函数调用中，15 个成功匹配到真实分发表，得到 74 个有源码位置、selector 和目标函数 ID 的候选边。例如多种 Stub 的：

```cpp
auto requestFunc = itFunc->second.first;
ret = (this->*requestFunc)(data, reply);
```

候选来自同类：

```cpp
memberFuncMap_[CMD_...] = {&SomeStub::OnHandler, {...permissions...}};
```

这证明计划中的确定性 `native_dispatch_map` 恢复不是只对 sensors 样例有效，在网络管理核心仓库中会直接补充大量 Stub 到 handler 的真实边。

### 7.2 仍有盲区

- `NetConnServiceStub::OnRemoteRequest` 是唯一无候选点。其 `memberFuncMap_` 初始化分散在构造函数、`InitAll()` 和多个辅助初始化方法，当前诊断只按局部 owner class/表名匹配，跨初始化函数聚合还不完整。
- audio 的 53 个残余主要是 Taihe callback、模板成员函数指针、请求队列中的 `(*requestIter)()` 等，没有稳定 selector→目标分发表，不能套用 IPC map 规则。
- appspawn 的 `info.handleRecvMsg = HandleRecvMessage` 没进入 OH-22A 诊断结果，因为当前诊断只识别 `table[key] = &Qualified::Target` 和括号间接调用，不识别结构体字段回调注册。
- 多个仓库残余数为 0，但源码审计仍发现线程/回调缺边。因此“残余为 0”不等价于“调用图完整”。

## 8. OpenHarmony 语义图现状

5 个仓库生成了 `semantic_graph.json`：

| 仓库 | 节点 | 边 | orphan | `transaction_to_handler` |
|---|---:|---:|---:|---:|
| communication_netmanager_base | 57 | 56 | 28 | 0 |
| hiviewdfx_hiview | 38 | 30 | 60 | 0 |
| multimedia_audio_framework | 731 | 703 | 1,402 | 0 |
| startup_init | 12 | 9 | 18 | 0 |
| telephony_core_service | 22 | 21 | 42 | 0 |

9 个仓库中，语义图对 reachable 新增边总数均为 0；所有数据集的 `units_with_semantic_context` 也是 0。原因不是语义图完全为空，而是目前大多只有 interface→transaction 或 proxy→transaction，缺少 transaction→handler，无法形成函数→语义节点→函数的完整路径。

## 9. 优化建议与顺序

### P0：新增 OpenHarmony native socket 边界入口

这是验收数据集上影响最大的缺口，应先于单纯扩大 BFS 深度处理。

建议第一小阶段只识别强证据原语，并保留结构化证据：

- 网络/Unix socket：`accept`、`accept4`、`recv`、`recvfrom`、`recvmsg`、`recvmmsg`；
- 分类：`network_socket`、`local_socket`、`kernel_socket`、`unknown_socket`；
- 信任级别不要一律写成完全不可信：互联网/网络连接通常为 `untrusted`，Unix 本地 socket 在校验 `SO_PEERCRED` 前为 `semi_trusted`，netlink/uevent 记为 kernel 边界；
- 所有直接读取函数均作为 reachable seed，但分类信息交给后续 Prompt 判断威胁模型；
- 暂不把普通 `read()` 一律当作 socket 输入，避免文件读取误报。`read()` 需要后续 fd 来源追踪。

预期直接改善：当前强原语抽样的 socket 入口覆盖从 0/40 提升到接近 40/40，并保留这些入口向下的解析/校验路径。

### P1：实现 OH-22B 确定性分发表补边

将已验证的 74 个候选变成带 provenance 的 `native_dispatch_map` 边，并接入调用图、reachable 和 Unit 上下文。先支持证据闭环的同类/同表映射；再扩展跨初始化函数聚合，以覆盖 `NetConnServiceStub`。

该阶段不能替代 socket 入口检测：它主要解决 Binder Stub→handler，而不是 socket accept/recv 边界。

### P2：补充线程/回调注册诊断与确定性边

优先支持本轮出现频率高、证据清晰的形式：

- `std::thread(&Class::Method, this, ...)`；
- `field = Handler` 后将包含该结构体的对象传入注册/事件循环 API；
- 构造函数/普通函数参数中的 callback 传递；
- listener 注册与 `OnEventPoll` 一类虚回调。

先产出诊断事实，再仅对目标唯一、类型/作用域一致的注册关系自动补边。多候选情形保留残余，不直接污染调用图。

### P3：LLM 残余调用恢复

LLM 只处理 P1/P2 无法确定的残余，例如 audio 中 callback 容器、模板函数指针和跨层封装。输入应是函数索引搜索结果、调用点局部源码、候选定义和已有边；输出必须带证据和置信度，按 BFS 逐层扩展并设置预算/深度/候选上限。

不建议让 LLM 扫描全部调用点：成本高、不可复现，而且会把本可确定求解的 74 条网络 Stub 边变成概率判断。

### P4：补全 IPC transaction→handler

当前语义图在本数据集上没有形成任何可用于 reachable 的函数到函数桥接。需要用 OH-22B 的 native dispatch 事实和 IDL/数字 code 映射共同补全 handler 端，之后再评估语义图接入 reachable 的实际增益。

### P5：Unit 生成与 Web 大文件性能

在入口准确性稳定后，再优化大仓库：

- reachable 先行、Unit 上下文延迟生成；
- 避免每个 Unit 重复嵌入大量相同上下文；
- JSON 分片/索引化和 Web 分页读取；
- 为 parser、call graph、diagnostics、Unit generation、serialization 增加逐阶段耗时，先 profiler 后优化。

## 10. 风险与限制

- 本轮 socket 函数集合是强原语启发式审计，不是人工标注的完整真值集。
- `accept/recv` 既可能处理互联网输入，也可能处理受权限保护的本地或 kernel 消息；入口识别不等价于漏洞结论。
- 某些接收函数可能是客户端读取服务端响应，仍属于外部输入边界，但攻击者能力取决于连接对象，需在安全分析阶段进一步判断。
- 未运行 LLM Detect/Verify，所以本记录不能证明漏洞发现率或误报率。
- 未分析 Rust/ETS/TS 路径；若验收范围包含这些语言，需要另行定义覆盖目标。
- 当前工作树已有用户和前序阶段改动，本轮未清理或覆盖它们。

## 11. 判定

当前项目对 9 个仓库的 C/C++ 生产源码扫描和 tree-sitter 函数抽取是稳定可运行的，普通直接调用图也有较好基础；但针对本次以 socket 为重点的验收目标，**当前 reachable 结果还不能称为全面可靠**。

首要原因是 native socket 输入边界没有成为入口，导致 40 个直接接收函数仅 3 个可达；其次是线程、函数指针和事件循环注册边缺失。OH-22A 在网络管理仓库中找到了 74 条可审计的确定性候选边，说明后续分层方案有效：先补 socket 入口和确定性分发/回调边，再把 LLM 用于真正无法静态消歧的残余。
