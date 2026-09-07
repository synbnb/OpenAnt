# hyl项目完整流程运行逻辑



## 1. 总览

有两条可以组合的主路径：

1. 用户已经知道本地源码路径时，直接运行扫描流程；
2. 用户只知道服务名、Unix socket 路径或一段自然语言描述时，先通过
   OpenGrok 源码定位器寻找对应 OpenHarmony 仓库，用户确认后再拉取并进入扫描。

静态扫描主线如下：

~~~text
用户输入
  ├─ 本地路径 / Git URL
  └─ 服务名、socket 路径或自然语言目标
       │
       ├─ （可选）OpenGrok 源码定位
       │      ├─ 目标标准化
       │      ├─ OpenGrok 探测与检索
       │      ├─ 源码证据追踪
       │      ├─ 服务端/客户端角色归因
       │      ├─ Manifest 仓库映射
       │      ├─ 用户确认
       │      ├─ Git 拉取
       │      └─ 拉取后校验与扫描交接
       │
       └─ 扫描任务
              ├─ 参数、项目、模型和平台检查
              ├─ 语言检测与源码解析
              ├─ 函数索引、原生调用图、入口点
              ├─ processing_level 可达性过滤
              ├─ application_context / OpenHarmony 安全基线
              ├─ 可选 LLM 可达性复核
              ├─ 可选 OpenHarmony 调用图语义阶段
              ├─ 可选 Agentic 上下文增强
              ├─ Stage 1 漏洞分析
              ├─ 可选 Stage 2 证据补充与攻击模拟
              ├─ pipeline_output.json
              ├─ 可选动态测试
              └─ 中英文摘要、HTML 和披露文档
~~~

## 2 OpenGrok 源码定位前置流程

### 2.1 适用场景

当用户不知道服务对应的 OpenHarmony 仓库时，可以输入：

- /dev/unix/socket/paramservice；
- init_control_fd；
- “我想分析参数服务”；
- 某个 NAPI、SA、HDF/HDI 或系统服务名称。

定位器的目的不是直接猜一个 Git URL，而是建立“目标描述 → 源码证据 →
Manifest 项目 → GitCode 仓库”的可审计链路。

### 2.2 状态机

~~~text
INTAKE
  → NORMALIZE_TARGET
  → PROBE_OPENGROK
  → SEARCH_INITIAL
  → TRACE_EVIDENCE
  → ATTRIBUTION_SERVER
  → LOCATE_CLIENT_COMM
  → RESOLVE_REPOSITORIES
  → VERIFY_EVIDENCE
      ├─ 证据不足且启用 LLM：RECOVER_EVIDENCE → TRACE_EVIDENCE
      └─ 无论强制谓词是否全部满足：AWAIT_USER_CONFIRMATION
  → CLONE
  → POST_CLONE_VERIFY
  → HANDOFF
  → DONE
~~~

还可能进入以下终态或暂停态：

- PARTIAL：已有部分证据，但仍有不确定性；
- NEEDS_REVIEW：需要用户或人工进一步判断；
- OPENGROK_UNAVAILABLE：OpenGrok 不可访问；
- VERSION_MISMATCH：源码版本、Manifest 或目标版本不一致；
- CLONE_FAILED：Git 拉取失败；
- POST_CLONE_VERIFY_FAILED：拉取后路径或符号校验失败；
- CANCELLED：用户主动取消；
- FAILED：不可恢复的内部错误。

“服务端强制谓词未全部满足”不再直接等价于失败。谓词缺失会作为警告和
missing_predicates 展示，但仍会进入用户确认，避免确定性规则把可能有效的
候选仓库硬性裁掉。

### 2.3 目标标准化

目标标准化器会从自然语言中提取：

- 原始用户描述；
- 目标关键词；
- 可能的 socket、SA、路径、服务名或宏名；
- 可选目标版本；
- 是否要求服务端、客户端或完整通信链路；
- 后续检索的语言和路径限制。

标准化结果写入 target.json。它只表达检索目标，不直接决定最终仓库。

### 2.4 OpenGrok 探测和确定性检索

探测阶段会检查配置的 OpenGrok 地址和能力。检索阶段使用受限工具：

- search_full：检索字符串或表达式；
- search_definition：检索宏、函数或符号定义；
- search_symbol：检索符号声明、定义和引用；
- search_path：列出目录下的关联源码；
- read_file：读取某个候选文件的源码证据。

检索结果会被整理为带唯一 ID 的证据项，例如：

~~~text
证据 ID：E-xxxx
文件：base/startup/init/.../param_utils.h
行号：79-80
事实：宏定义引用 /dev/unix/socket/paramservice
~~~

结果不是把 OpenGrok 全部返回给模型，而是经过数量、路径、查询长度和证据
预算限制后，保留候选路径、命中行和可读源码片段。

### 2.5 LLM 语义检索

在 Web 中勾选 LLM 语义检索，或使用 CLI 的 --llm-search 后，定位器会在
确定性检索之后启动有界 agentic loop：

- 默认最多 20 个工具动作；
- 默认最多 21 次模型调用；
- 单次查询最长 512 字符；
- 可见证据 ID 和提示词大小有上限；
- 模型可以选择受限的搜索、读文件和符号追踪动作；
- 重复动作会返回重复反馈，要求模型更换查询；
- OpenGrok 工具不能执行 shell、clone 或自行决定 Git URL；
- 所有模型动作都写入事件流，包含轮次、动作、工具结果和证据 ID。

LLM 的作用是根据已经得到的事实决定“下一步查什么”，不是替代证据存储器
或仓库映射器。模型不能把自己的猜测当成仓库 URL。

### 2.6 源码追踪和角色归因

Trace 阶段读取候选文件附近的源码，补足：

- socket 创建、监听、连接和消息处理；
- 服务初始化、注册和生命周期；
- 客户端调用、代理和回调；
- 宏展开后的路径关系；
- 函数之间的调用或数据传播。

服务端/客户端归因可以使用专门的 LLM 角色判断，但只针对符合路径和证据
条件的源码。明确属于 test、tests、unittest、fuzz 或 fuzzing 的内容不会被
当作生产服务端或客户端证据。kernel、third_party、generated、out、build
本身不会被一概排除；如果证据与目标相关，仍可以呈现给模型，最终由角色归因
判断其生产意义。

### 2.7 Manifest 仓库映射

定位器会结合 OpenHarmony Manifest、目录前缀和项目配置，将源码路径映射为：

- GitCode project 名称；
- 仓库 URL；
- 目标分支或 revision；
- 源码路径前缀；
- 映射证据和可信度。

仓库 URL 必须来自可验证的 Manifest 映射。模型不能凭空生成一个仓库地址。

### 2.8 证据复核与用户确认

校验阶段会检查服务端角色、通信边界、Manifest 映射、目标路径和版本等谓词。
缺失谓词会记录为 warning，但不会阻止确认界面。

confirmation_summary.json 是用户确认前的核心摘要，包含：

- 原始目标和标准化目标；
- 建议拉取的 GitCode 项目、URL、revision；
- 预计落盘目录；
- 服务端和客户端候选路径；
- 关键证据及文件行号；
- 缺失谓词、版本警告和风险提示。

用户必须在 Web 中点击确认后才会执行 Git 拉取。拒绝时可以填写原因或约束，
定位器会保留证据，不删除已有结果，并允许带反馈继续检索。取消和删除会话
不会删除已经拉取到 source_code_base 的仓库。

### 2.9 Git 拉取、拉取后验证和交接

CLONE 阶段只执行经过映射校验的仓库拉取。clone_results.json 记录：

- 实际命令摘要；
- URL 和目标目录；
- stdout/stderr 摘要；
- 返回码；
- 是否成功。

POST_CLONE_VERIFY 会检查：

- origin 是否与确认的仓库一致；
- HEAD、revision 或分支是否符合目标；
- 关键源码路径是否存在；
- 目标符号和字面量是否能在拉取后的仓库中找到。

通过后写入 source_handoff.json。Web 可以直接使用其中的
primary_analysis_repo 预填普通扫描表单。

### 2.10 定位器产物

定位会话保存在：

~~~text
~/.openant/webui/source-locator/<locator-id>/
~~~

常见产物：

| 文件 | 作用 |
| --- | --- |
| session.json | 当前状态、目标、配置和错误 |
| target.json | 目标标准化结果 |
| probe.json | OpenGrok 能力探测结果 |
| search_plan.json | 初始检索计划和查询摘要 |
| evidence.json | 追加式源码证据存储 |
| evidence_graph.json | 证据之间的引用和关系 |
| attribution.json | 服务端、客户端和不确定角色 |
| repository_candidates.json | Manifest 仓库候选 |
| confirmation_summary.json | 用户确认界面使用的摘要 |
| clone_results.json | Git 拉取命令和结果 |
| post_clone_verification.json | 拉取后路径、符号和 revision 校验 |
| source_handoff.json | 交接给普通扫描器的路径和元数据 |
| events.jsonl | 按时间追加的阶段事件和模型动作 |



## 3. 普通扫描任务初始化

### 3.1 仓库输入

扫描器接受：

- 本地源码目录；
- Git URL（Go CLI 会先 clone）；
- 源码定位器 handoff 后的本地目录。

初始化时会把仓库和输出路径转为绝对路径，创建输出目录，读取配置，初始化
成本统计和阶段注册表，并记录本次扫描参数。

### 3.2 可选的主要扫描参数

| 参数 | 当前作用 |
| --- | --- |
| --platform auto/generic/openharmony | 选择平台画像和解析分支 |
| --language / --languages | 选择单语言或多语言解析 |
| --level all/reachable/codeql/exploitable | 选择分析范围 |
| --verify | 启用 Stage 2 |
| --no-context | 关闭应用上下文 |
| --no-enhance | 关闭 Agentic 上下文增强 |
| --enhance-mode agentic/single-shot | 选择增强模式 |
| --dynamic-test | 请求动态测试 |
| --dynamic-test-mode docker/claude-code | 选择动态测试方式 |
| --skip-tests | 是否跳过测试内容，默认开启 |
| --library-mode | 保留库型仓库的导出 API |
| --limit | 限制后续分析单元数量，不限制 LLM 可达性复核 |
| --workers | 并发 worker 数量 |
| --llm-reachability | 启用 LLM 入口和可达性复核 |
| --llm-call-graph-recovery | 启用 OH 残余调用边单轮复核 |
| --llm-call-graph-iterative-recovery | 启用 OH 入口驱动的多轮恢复 |
| --llm-call-graph-candidate-review | 复核确定性候选边 |
| --llm-call-graph-projection | 将高置信语义边做增量可达性投影 |
| --openharmony-dispatch-code-evidence | 提取分派码证据 |

### 3.3 项目、差分和断点

Go CLI 可以把扫描关联到一个项目，记录：

- repository URL 和本地路径；
- source revision；
- full、incremental、diff、PR 或 staged 扫描模式；
- 基线 revision 和差分范围；
- 已完成阶段和 checkpoint。

断点文件只用于恢复同一任务，不会把不同 scan-id 的历史产物合并。发生失败时，
能安全复用的阶段产物会保留；依赖缺失产物的后续阶段会标记为 skipped 或
failed，并在 scan.report.json 中说明。

## 4. 平台检测与源码解析

### 4.1 平台选择

platform=auto 时，扫描器会尝试从仓库内容构建 OpenHarmony 平台画像。如果检测
到有效画像，就把本次有效平台提升为 openharmony；检测不完整时不会伪造完整
画像，也不会因为画像检测失败而直接终止普通扫描。

platform=openharmony 会强制使用 OpenHarmony 解析和上下文逻辑，即使画像只包含
最小平台标记。platform=generic 不主动读取 OpenHarmony 专用元数据。

解析后 platform_profile.json 会同步实际发现的文件统计，避免把“仓库文件数”
错误显示成零。

### 4.2 文件枚举和测试内容

解析器会遍历受支持扩展名和语言配置中的源码文件。通用无关目录、缓存和版本
控制目录会按语言解析器规则跳过。

OpenHarmony 生产归因的特殊规则是：

- test、tests、unittest、fuzz、fuzzing 路径不作为生产服务端或客户端的主要
  归因依据；
- kernel、third_party、generated、out、build 不会仅因目录名称被删除；
- 测试和模糊测试代码仍可以作为上下文或诊断信息出现，但不能单独证明生产
  服务入口；
- --skip-tests 会影响解析和筛选范围，具体结果会写入解析阶段报告。

### 4.3 函数单元

Tree-sitter 或语言对应的 AST 提取函数和方法单元，通常包含：

- 稳定单元 ID；
- 函数名、限定名和签名；
- 文件相对路径；
- 起止行号；
- 完整函数源码；
- 参数和返回值；
- 入口标志；
- 调用者和被调用者信息；
- 平台、文件角色和安全元数据。

dataset.json 是后续阶段的主要单元输入。解析器还会保存 analyzer_output.json，
其中包含函数索引、入口提示、结构化诊断和解析统计。

### 4.4 原生调用图

调用图主要由解析器根据 AST 和符号信息建立，常见产物为：

~~~text
call_graph.json
call_graphs.json
<language>/call_graph.json
~~~

图中通常包含函数节点、直接调用边、反向调用关系和入口标记。它是确定性
结构事实的来源。OpenHarmony 语义图或 LLM 恢复结果默认不会覆盖原生图。

### 4.5 processing_level 和 BFS

processing_level=all 保留所有解析单元。

processing_level=reachable 时，入口检测器先选择结构化入口，再在原生调用图上
从入口执行 BFS，保留入口向下可达的函数。入口可能来自：

- Binder、SA、IDL、Stub/handler；
- NAPI、HDF/HDI、ioctl、socket 或文件回调；
- 注册表、服务初始化和导出 API；
- 语言解析器提供的结构化入口标记。

真实入口种子为空时，扫描器采用“保召回”安全策略，将全部单元传给下游，并在
日志和报告中标记入口缺失，而不是得到一个空数据集。

### 4.6 多语言扫描

多语言解析会按语言写入子目录，再合并为顶层：

~~~text
<output>/<language>/dataset.json
<output>/<language>/analyzer_output.json
<output>/<language>/call_graph.json
<output>/dataset.json
<output>/analyzer_output.json
<output>/call_graphs.json
~~~

后续应用上下文、增强、分析和验证通常对合并后的 dataset 运行一次。非严格
模式下某一种语言解析失败可以降级继续；严格模式会让失败变成任务错误。

## 5. OpenHarmony 专用解析产物

当有效平台为 openharmony 时，C/C++ 解析器会尽量生成额外产物：

| 文件 | 作用 |
| --- | --- |
| scan_results.json | OpenHarmony 入口、服务和结构扫描结果 |
| semantic_graph.json | 平台语义注册、分派和边的附加图 |
| call_graph_residuals.json | 解析器认为可能存在间接调用或未解析关系的位置 |
| dispatch_recovery_diff.json | 分派解析前后的差异诊断 |

这些产物用于诊断、入口补充和可选语义阶段。默认情况下：

- semantic_graph 是可供后续使用的附加证据；
- native call_graph.json 仍然保持解析器原貌；
- 不会因为某条语义边存在就无条件改写 native graph；
- 任何不能由源码证据支持的模型猜测都不会写入确定性调用图。

## 6 应用上下文和 OpenHarmony 安全基线

### 6.1 上下文来源优先级

如果仓库根目录有 OPENANT.THREATMODEL.md，会优先加载它，再与 OpenHarmony
最低安全基线合并。仓库模型不能删除平台基线约束。

没有仓库模型时，模型生成 application context，再合并平台画像。上下文通常
包含：

- application_type；
- 代码和组件范围；
- 攻击者画像；
- 外部输入源；
- 信任边界；
- 漏洞判定标准；
- 排除项和来源 provenance。

结果写入 application_context.json。

### 6.2 OpenHarmony 基线

OpenHarmony 平台上下文重点要求模型同时审查：

- Binder、System Ability、IDL 和 MessageParcel；
- 调用者身份、权限和隔离边界；
- 空容器、空指针元素、长度、计数和索引；
- 内存安全、整数和尺寸计算；
- 文件、socket、NAPI、HDF/HDI、ioctl；
- 并发、生命周期、回调和状态机；
- 信息泄露、资源耗尽、服务崩溃和拒绝服务。

“权限检查通过”不等于“输入已经安全”。授权的系统应用仍可能提交空、
畸形、超大或状态不一致的参数。

### 6.3 上下文阶段失败

上下文是重要增强信息，但当前实现允许可选降级。生成失败时：

- 阶段报告标记 skipped 或 failed；
- scan.report.json 记录原因；
- 扫描继续运行；
- 后续模型收到的安全背景可能不完整。

使用 --no-context 是用户的明确选择；如果仓库有安全模型，日志会提示该模型
没有被使用。

## 7. 可选的 LLM 语义阶段

这些阶段均在解析之后、Agentic 增强和漏洞分析之前运行。

### 7.1 LLM 可达性复核

开关：--llm-reachability。

执行逻辑：

1. 让模型查看完整函数集合，而不是只看 --limit 截断后的单元；
2. 每个函数默认最多提供 1500 字节代码，可通过参数调整；
3. 模型输出入口、外部输入或可达性信号及理由；
4. 将信号写入 llm_reachability.json；
5. 把模型提升的入口作为额外 BFS 种子；
6. 有原生调用图时重新做结构可达性过滤；
7. 没有调用图时为避免误删，保留全部单元并警告成本增加。

该阶段不直接改写原生调用图。它主要解决“结构入口规则漏掉一个真实入口”
的问题。

### 7.2 OpenHarmony 调用图恢复

开关：

- --llm-call-graph-recovery：单轮残余复核；
- --llm-call-graph-iterative-recovery：入口驱动的有界多轮复核。

输入包括：

- call_graph.json；
- call_graph_residuals.json；
- 函数索引；
- dataset 中的入口提示；
- iterative 模式可选的 semantic_graph.json。

输出：

- 单轮：llm_call_graph_recovery.json；
- 迭代：llm_call_graph_recovery_rounds.json。

模型只能提交带证据的候选边、拒绝理由或未决项。模型不能直接修改
call_graph.json，也不能凭空把一条边变成确定事实。

### 7.3 候选边复核

开关：--llm-call-graph-candidate-review。

该阶段复核确定性解析器已经找到的候选边，写入
llm_call_graph_candidate_review.json。默认是审计性产物，不改变 native graph
和 dataset 可达性。

### 7.4 语义边投影

开关：--llm-call-graph-projection。

投影阶段读取恢复或候选复核产物，写入 llm_call_graph_overlay.json。对于
processing_level 不是 all 的任务，扫描器会保留完整的
dataset_unfiltered.json，然后使用“只增不减”的 overlay BFS：

- 可以因为高置信新边把漏掉的单元重新纳入；
- 不会因为语义图删掉原生图已确认的单元；
- 会做单调性检查，防止投影导致召回范围缩小。



## 8. Agentic 上下文增强

增强开关默认开启，模式默认为 agentic；也可以使用 --no-enhance 或
--enhance-mode single-shot。

增强器读取：

- 当前 active dataset；
- analyzer_output 和函数索引；
- 仓库源码；
- application_context；
- 可用的原生调用者、被调用者和平台语义证据。

它为单元补充：

- 上下游调用上下文；
- 入口到目标的关系说明；
- 安全边界和输入传播；
- OpenHarmony IPC/SA/IDL、NAPI、HDF/HDI 等平台线索；
- 语义分类、调用理由和不确定性。

产物是 dataset_enhanced.json。Agentic 增强不会自动把所有模型猜测写回
call_graph.json；漏洞分析使用增强后的单元上下文，但仍应把确定性图和模型
推理区分开。

增强失败时，会保留原 dataset 作为 active 输入，并在阶段报告中记录降级。
增强器支持 checkpoint，因此大型仓库可以从已完成单元继续。

## 9. Stage 1：漏洞分析

### 9.1 输入

Stage 1 使用：

- active dataset（通常为 dataset_enhanced.json）；
- application_context.json；
- analyzer_output.json；
- 原生调用图和平台附加证据；
- 仓库中的实际源码。

默认并行处理，worker 数量由 --workers 控制。每个分析单元会生成一个严格
JSON 结果，再由程序校验和汇总。

### 9.2 模型分析框架

当前漏洞提示词不再要求模型必须构造完整 weaponized payload。模型分别判断：

1. 缺陷是否存在；
2. 外部边界是否可达；
3. 可能造成的安全影响；
4. 证据是否足够完整。

覆盖范围包括：

- IPC/Parcel、IDL、长度和字段顺序；
- 授权、认证和隔离绕过；
- 空指针、越界、UAF、双重释放和泄漏；
- 整数溢出、截断和尺寸乘法；
- 解析器、压缩、递归、索引和资源耗尽；
- 竞态、死锁、生命周期和异步回调；
- 类型转换、ABI 和枚举/宽度错误；
- 文件、socket、NAPI、HDF/HDI、ioctl；
- 日志、密钥、明文传输和信息泄露；
- 状态机、重放、重复请求和错误路径。

授权调用者仍可能发送畸形参数。权限校验只能证明授权关系，不能代替空值、
边界、生命周期或资源检查。

### 9.3 结果分类

每个单元的 finding 为：

- safe：没有证据支持相关缺陷；
- protected：存在怀疑，但有具体防护覆盖每条危险路径；
- vulnerable：缺陷、可达性和至少一种安全影响都有证据支持；
- inconclusive：缺少关键调用边、sink、guard、下游实现或影响证据。

缺少下游实现时，不应仅凭“看起来有权限检查”返回 protected；同样也不能仅
凭类型转换或参数转发就断言一定可利用。Stage 1 会把未知事实写入
missing_evidence。

### 9.4 产物

~~~text
results.json
analyze.report.json
~~~

results.json 保留每个分析单元的 reasoning、漏洞类别、影响、攻击场景、前置
条件、数据流、guard 分析、证据、反证、缺失证据、CWE 和置信度。

## 10. Stage 2：证据补充和攻击模拟

开关：--verify。

### 10.1 哪些单元进入 Stage 2

Stage 2 不需要重新分析所有 safe 单元。默认重点处理：

- vulnerable；
- bypassable；
- inconclusive。

protected 和 safe 通常不会进入 Stage 2，除非上游结果被重新分类。

### 10.2 FindingVerifier 工具

验证器可以在仓库函数索引和源码上使用：

- search_usages：查找调用和引用；
- search_definitions：查找定义；
- read_function：读取完整函数；
- list_functions：浏览候选函数；
- finish：提交验证结论。

模型会围绕 Stage 1 的证据缺口补充调用者、被调用者、权限 guard、输入
传播和危险 sink，必要时进行攻击者视角的模拟。

### 10.3 结果

产物：

~~~text
results_verified.json
verify.report.json
~~~

验证结果会合并为 agreed、disagreed、needs_review 和 confirmed 等统计。一个
inconclusive 单元可能在补足证据后变为 safe、protected 或 vulnerable，也可能
继续保持未决。

Stage 2 失败时，扫描器通常保留 Stage 1 结果并记录降级原因，不会伪造“已验证”。

## 11. 构建统一输出

build-output 阶段把当前有效结果统一成 pipeline_output.json，供动态测试、
报告生成和 Web 使用。

程序会：

- 读取 results.json 或 results_verified.json；
- 规范化模型返回的数组和对象；
- 从 results、dataset、call graph 补齐源码；
- 去重 caller/callee；
- 合并阶段报告、平台画像、上下文 provenance 和跳过原因；
- 计算 finding、漏洞、验证和成本指标。

pipeline_output.json 是跨阶段契约，不是模型原样输出。即使没有漏洞，也会
生成该文件，供 Web 显示“扫描完成但没有确认问题”。

## 12. 动态测试

### 12.1 触发条件

动态测试阶段只有在以下条件都满足时才真正执行或准备任务：

1. 用户请求了动态测试；
2. Stage 1 仍有 vulnerable、bypassable 或 inconclusive 候选，使扫描器进入
   动态阶段；
3. 运行模式所需环境可用。

进入动态阶段后，Docker 动态执行器还会再次收窄范围，只接受
pipeline_output 中 stage2_verdict 为 confirmed、agreed 或 vulnerable 的条目。
因此“进入动态阶段”和“实际执行一个 finding”是两件事。如果 Stage 2 只留下
rejected、protected、safe 或 inconclusive，动态执行器会生成空结果并正常结束。
如果扫描器根本没有上述三类初步候选，阶段会标记为 no_candidates，不会启动
空测试任务。

### 12.2 Docker 模式

dynamic_test_mode=docker 时，Python 动态测试器会：

1. 选择 Stage 2 可测试的 finding；
2. 让模型生成动态测试计划或载荷；
3. 构建隔离容器；
4. 在容器内执行测试；
5. 读取并校验结构化结果；
6. 最多按配置重试，默认重试次数为 3；
7. 生成 CONFIRMED、NOT_REPRODUCED、BLOCKED、INCONCLUSIVE 或 ERROR。

产物通常包括：

~~~text
dynamic_test_results.json
dynamic_test_results.md
dynamic-test.report.json
~~~

Go CLI 在请求 Docker 动态测试前会预检查 Docker。Docker 不可用时，任务会
安全地跳过或失败并保留原因。

### 12.3 Claude Code 模式

dynamic_test_mode=claude-code 时，Python 不在扫描进程内直接运行 Claude Code；
它先准备一个受限任务工作目录。Web Go 服务随后启动 Claude Code PTY，把终端
输出转成 SSE 并显示在动态测试菜单中。

任务目录结构类似：

~~~text
<scan>/run-<timestamp>-<id>/task/
  CLAUDE.md
  TASK.md
  task_manifest.json
  context/
    pipeline_output.json
    candidate_manifest.json
    artifact_manifest.json
    source_code.json
  static_artifacts/
  source_code -> 实际仓库
  .claude/skills/openant-openharmony-dynamic/SKILL.md
  results/
~~~

工具公开目录位于任务目录上一级的 openharmony-public-tools，包含可用的 hdc、
hvigorw、node、hap-sign-tool.jar 等本地工具链接和说明。密钥不会被复制到
任务包。

Claude 任务要求：

- Claude Code 已安装；
- 任务目录可读写；
- 若执行 HAP 或设备交互，需要本地 HarmonyOS 工具链；
- 若执行设备测试，需要开发板、hdc 连接和相应权限；
- Claude 只能把结果写入 results/，不得修改 context/ 或源码仓库。

Web 会话结束后，Go 服务收集 results/，写入动态测试结果，回填
pipeline_output，并再生成中英文报告。终端中的 Ink 边框、空白刷新帧和控制
字符会被过滤；如果终端窗口仍出现异常，优先检查 PTY、SSE 和浏览器字体渲染。

## 13. 报告生成

### 13.1 Python 报告

如果启用报告，报告器读取 pipeline_output 和动态结果，生成：

~~~text
report/SUMMARY_REPORT.md
report/disclosures/DISCLOSURE_*.md
~~~

摘要和披露文档可以使用英文或中文模板。报告器会从同目录和 sibling 产物中
补齐源码片段，避免只输出 Vulnerable 而缺少 Vulnerable Code、路径和函数。

### 13.2 Web 报告

Web 任务会确保存在：

~~~text
report.html
report.zh-CN.html
summary.md
summary.zh-CN.md
report/disclosures/
~~~

报告去除不需要的第三方署名文案，并在披露条目列表中直接展示文件路径、函数
名和漏洞简述。完整证据仍可点进单个条目查看。

### 13.3 scan.report.json

最后由扫描器聚合：

- 各阶段状态、开始结束时间和耗时；
- token、调用次数和费用；
- 单元数、漏洞分类和 Stage 2 统计；
- 动态测试状态；
- skipped、failed 和降级原因；
- 关键产物路径。

## 14. Web 页面如何对应扫描流程

Web 顶部是统一实时日志，不再把长日志挤在每个阶段卡片中。阶段菜单一般按
以下顺序显示：

1. 源码解析；
2. 应用上下文；
3. LLM 可达性复核（可选）；
4. OpenHarmony 调用图语义阶段（有产物时显示）；
5. Agentic 上下文增强；
6. 漏洞分析；
7. 结果验证；
8. 统一输出；
9. 动态测试；
10. 报告生成。

每个阶段有：

- 当前状态；
- 简短的输入、处理和输出说明；
- 关键结果字段；
- 阶段日志入口；
- 产物列表；
- 原始 JSON 查看；
- 中文字段解释的友好查看。

大型 JSON 不会一次性把全部内容渲染到 DOM。dataset 和 pipeline_output 使用
分页、搜索、字段折叠和按单元加载；调用图使用节点、边、入口和层级浏览，
避免一次渲染几千个节点导致浏览器卡顿。

## 15. 产物目录示例

一次普通 Web 扫描的典型目录如下：

~~~text
~/.openant/webui/<scan-id>/
  meta.json
  logs.txt
  platform_profile.json
  dataset.json
  dataset_enhanced.json
  analyzer_output.json
  call_graph.json
  call_graph_residuals.json
  semantic_graph.json
  application_context.json
  llm_reachability.json
  results.json
  results_verified.json
  pipeline_output.json
  scan.report.json
  parse.report.json
  app-context.report.json
  enhance.report.json
  analyze.report.json
  verify.report.json
  build-output.report.json
  dynamic-test.report.json
  report/
    SUMMARY_REPORT.md
    disclosures/
  report.html
  report.zh-CN.html
~~~

并不是每次都会产生所有文件：

- 未开启 LLM 可达性时不会有 llm_reachability.json；
- 未开启 OpenHarmony 恢复时不会有恢复报告；
- 未开启 Stage 2 时通常没有 results_verified.json；
- 没有候选或未请求动态测试时，动态结果可能只有 skipped 报告；
- --no-report 时不会生成摘要和披露文档。

## 16. 一个完整例子：从参数服务 socket 到漏洞报告

下面的例子把源码定位器和普通扫描器串成一条完整链路。它不是只展示“找到哪个
仓库”，还说明每个阶段产生什么文件、下一阶段读取什么内容，以及用户在哪里
可以查看或干预流程。

### 16.1 用户提出目标

用户在 Web 定位窗口输入：

~~~text
我想分析 /dev/unix/socket/paramservice 这个 OpenHarmony 服务。
~~~

此时用户还没有提供本地源码路径，也可能不知道 OpenHarmony 的仓库名称。
定位器将自然语言目标转成受限目标规格，例如：

~~~json
{
  "kind": "unix_socket",
  "value": "/dev/unix/socket/paramservice",
  "platform": "openharmony",
  "source_scope": "production"
}
~~~

### 16.2 源码定位器搜索和确认

定位器按以下顺序工作：

1. **探测 OpenGrok。** 检查代码平台是否可访问、索引是否正常，并记录探测
   事件；探测失败时不会假装搜索成功。
2. **搜索完整 socket 路径。** 搜索
   `/dev/unix/socket/paramservice`，得到
   `base/startup/init/services/param/include/param_utils.h` 中的
   `CLIENT_PIPE_NAME` 和 `PIPE_NAME` 宏定义。
3. **读取服务端实现。** 打开 `param_service.c`，确认 `InitParamService`、
   `g_paramService` 以及服务初始化日志，判断这是参数服务而不是普通字符串引用。
4. **沿符号追踪服务端链路。** 继续查找 `CmdServiceInit`、其实现、
   `ProcessControlFd` 和消息处理回调，记录 socket 初始化、监听和请求处理的
   文件及行号。
5. **沿符号追踪客户端链路。** 查找 `CmdClientInit`、`CmdAgentCreate` 以及
   `begetctl` 等调用者，区分“创建/监听 socket 的服务端”和“连接 socket 的
   客户端”。
6. **展开宏和间接引用。** 如果源码使用 `PIPE_NAME`、
   `STARTUP_INIT_UT_PATH` 或其他宏，定位器会继续查定义，避免只凭一处日志或
   字符串命中下结论。
7. **排除非生产归因。** `test`、`tests`、`unittest`、`fuzz` 和 `fuzzing`
   路径不会单独作为服务端/客户端生产证据；`kernel`、`third_party`、
   `generated`、`out`、`build` 不会仅因目录名被删除。
8. **解析仓库映射。** 从 Manifest、bundle 或仓库元数据把
   `base/startup/init` 映射到 GitCode 仓库 `startup_init`，同时收集仓库 URL、
   默认 revision 和建议的本地目录名。
9. **进行服务端强制谓词复核。** 复核目标路径、服务端初始化、客户端通信和
   仓库映射是否分别有证据。若缺少“绑定或获取 socket”等证据，只记录到
   `missing_predicates`，不把缺证据直接当成“目标不存在”。
10. **展示确认卡片。** Web 页面显示目标 socket、服务端候选文件、客户端候选
    文件、关键代码片段、证据 ID、Git 仓库 URL、revision 和将要写入的目录。
    用户可以接受、拒绝，或给出“仓库不对”“需要继续查找客户端”等反馈。
11. **处理用户反馈。** 接受后进入拉取；拒绝或补充约束后，agentic loop 将
    约束加入下一轮检索，继续调用搜索/读文件工具，当前 Web 默认最多 20 轮，
    直到得到更好的候选、达到预算或需要再次确认。
12. **执行 Git 拉取和交接校验。** 用户确认后才执行 clone/fetch。拉取完成后
    检查目标目录、`origin`、HEAD/revision、关键文件和关键符号；失败时保留
    日志和证据，不启动普通扫描。

定位阶段的主要产物位于定位 session 目录：

~~~text
target_spec.json
evidence.json
evidence_graph.json
repository_candidates.json
repository_confirmation.json
post_clone_verification.json
source_handoff.json
events.jsonl
~~~

其中 `source_handoff.json` 至少包含普通扫描所需的本地源码绝对路径、仓库名、
URL、revision、平台和定位证据。普通扫描读取它之后，不再依赖 OpenGrok 的在线
页面，也不会把定位器的模型推测直接当作源码事实。

### 16.3 普通扫描器接管后的具体流程

假设用户接受 `startup_init`，仓库被拉取到
`OpenAnt/source_code_base/startup_init`，并在 Web 中点击“运行普通扫描”。
扫描器按以下顺序处理：

13. **初始化扫描任务。** 读取 handoff 中的源码路径和 revision，创建唯一的
    scan-id 和输出目录，加载 LLM、并发数、语言、`processing_level`、是否验证
    和是否动态测试等选项，写入 `scan_config.json` 或扫描事件。
14. **检测平台和枚举文件。** 根据仓库元数据和源码内容建立 OpenHarmony 平台
    画像；枚举 C/C++、IDL、JSON、GN 等相关文件，按当前筛选规则跳过测试和
    fuzz 代码的生产归因。此阶段产出 `platform_profile.json`、
    `file_inventory.json` 和 `parse.report.json`。
15. **Tree-sitter 提取函数单元。** 对生产源码提取函数名、限定名、签名、行号、
    完整函数体、参数和入口提示，同时建立函数索引。结果写入
    `analyzer_output.json`、各语言 `dataset.json` 和合并后的 `dataset.json`。
16. **构建原生调用图。** 根据 AST 调用表达式、符号解析和函数索引建立直接
    caller/callee 边。产出 `call_graph.json`、`call_graphs.json`；该图保留解析器
    事实，不会因为模型猜测而被静默覆盖。
17. **筛选可达范围。** 若选择 `processing_level=reachable`，从 Binder/SA/IDL、
    Stub/handler、NAPI、服务注册等入口执行 BFS；若没有可靠入口种子，则采用
    保召回策略保留全部单元并记录原因。`processing_level=all` 则直接保留全部
    单元。
18. **生成 OpenHarmony 专用证据。** 对本例重点识别 socket、服务初始化、控制
    FD、客户端连接和回调等结构，按需写入 `scan_results.json`、
    `semantic_graph.json`、`call_graph_residuals.json` 和分派证据文件。测试代码
    只能作为辅助上下文，不能单独证明生产服务入口。
19. **构建应用上下文。** 合并仓库安全模型和 OpenHarmony 最低安全基线，形成
    攻击者画像、输入源、信任边界、权限要求和漏洞判定标准，写入
    `application_context.json`。权限检查不会被当作输入、内存或生命周期校验的
    替代品。
20. **执行可选 LLM 语义阶段。** 如果用户开启 `--llm-reachability`，模型查看
    函数索引并补充入口信号，再做增量 BFS；如果开启调用图恢复、候选边复核或
    语义投影，则分别生成对应报告。所有模型边都带证据和置信度，不直接篡改
    native call graph。
21. **执行 Agentic 上下文增强。** 读取 `dataset.json`、调用图、源码和平台上下文，
    为每个分析单元补充上游调用者、下游调用者、输入传播、权限 guard、socket/IPC
    边界和不确定性，写入 `dataset_enhanced.json`。漏洞分析优先使用这个增强数据集。
22. **执行 Stage 1 漏洞分析。** 对每个单元分别判断缺陷、可达性、安全影响和
    证据完整性，覆盖输入校验、权限绕过、内存安全、资源耗尽、并发、生命周期、
    NAPI/HDF/HDI/socket 等类别。结果写入 `results.json` 和 `analyze.report.json`，
    finding 为 `safe`、`protected`、`vulnerable` 或 `inconclusive`。
23. **执行 Stage 2 证据补充。** 开启 `--verify` 后，FindingVerifier 对高风险或
    未决单元使用 `search_usages`、`search_definitions`、`read_function`、
    `list_functions` 和 `finish` 补充调用边、下游 sink 和 guard 证据，写入
    `results_verified.json` 和 `verify.report.json`。Stage 2 的确认仍是证据复核，
    不是设备运行时复现。
24. **构建统一输出。** `build-output` 合并 Stage 1/Stage 2、数据集、调用图、平台
    画像和动态测试状态，生成 `pipeline_output.json`。Web 的统计卡片、漏洞列表
    和动态测试候选均从这个跨阶段契约读取。
25. **按请求执行动态测试。** 用户没有开启动态测试时记录 skipped；开启后只把有
    可验证候选的条目交给 Docker 或 Claude Code 模式。动态结果写入
    `dynamic_test_results.json`、`dynamic-test.report.json`，并注明
    CONFIRMED、NOT_REPRODUCED、BLOCKED 或 INCONCLUSIVE。
26. **生成报告并更新 Web。** 报告器根据统一输出生成中英文摘要、逐条披露文档和
    HTML 报告。Web 按阶段展示日志、关键结果、原始 JSON、表单化字段、函数调用
    图、入口函数和动态测试工作目录；所有阶段文件都保存在同一个 scan-id 目录中。

### 16.4 本例的最终产物和结果流转

一次完整运行成功后，目录大致如下：

~~~text
<scan-id>/
  source_handoff.json                 # 定位器交给普通扫描器的入口
  platform_profile.json               # OpenHarmony 平台画像
  analyzer_output.json                # 函数索引和解析诊断
  dataset.json                        # 原始分析单元
  call_graph.json                     # 解析器原生调用图
  semantic_graph.json                 # 可选平台语义证据
  application_context.json            # 攻击者、输入源和安全基线
  dataset_enhanced.json               # Agentic 上下文增强数据集
  results.json                        # Stage 1 结果
  results_verified.json               # Stage 2 结果（启用时）
  pipeline_output.json                # 跨阶段统一结果
  dynamic_test_results.json           # 动态测试结果（请求时）
  scan.report.json                    # 总状态、统计、成本和跳过原因
  report/
    SUMMARY_REPORT.md
    SUMMARY_REPORT.zh-CN.md
    disclosures/
  report.html
  report.zh-CN.html
~~~

