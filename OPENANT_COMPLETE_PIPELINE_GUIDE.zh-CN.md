# OpenAnt 完整扫描主流程学习笔记

本文用于回看 OpenAnt 从接收仓库路径到生成最终扫描结果的完整流程，重点说明每个阶段的输入、处理方式、输出文件，以及哪些地方会调用大模型。

本文对应的核心实现位于 `libs/openant-core`。OpenAnt 还包含 Go CLI 层；Go CLI 主要负责命令行、项目目录和跨语言 JSON 契约，核心分析流程由 Python 实现。

## 1. 一句话总览

```text
repo_path
  -> 路径、配置和模型检查
  -> 语言检测与源码解析
  -> 函数索引、调用图、反向调用图
  -> 分析单元和有限深度上下文
  -> 入口点识别与可达性过滤
  -> 应用上下文 / 威胁模型
  -> 可选的 LLM 可达性判断
  -> 可选的 Agent 增强
  -> Stage 1 漏洞检测
  -> 可选的 Stage 2 攻击路径验证
  -> 构建 pipeline_output.json
  -> 可选的 Docker 动态测试
  -> 总结报告和漏洞披露文档
  -> scan.report.json
```

需要区分三类工作：

1. 解析器和索引器主要是确定性程序，不依赖大模型。
2. Stage 1、Stage 2、应用上下文、Agent 增强、动态测试用例生成和报告生成会调用大模型。
3. `pipeline_output.json` 和 `scan.report.json` 是 Python 按固定规则组装的文件，不是大模型直接生成的。

## 2. 初始输入

### 2.1 必需输入

最核心的输入是：

```text
repo_path
```

它可以是：

- 本地仓库目录；
- 远程 Git URL。Go CLI 会先 clone，再把本地 clone 目录交给 Python 扫描器。

### 2.2 常见配置输入

扫描还会读取：

- 输出目录；
- LLM provider 和模型配置；
- 是否启用 Agent 增强；
- 是否启用 Stage 2；
- 是否启用动态测试；
- 分析深度、worker 数量、重试次数和可选的分析数量限制；
- 应用上下文或威胁模型文件。

Go CLI 和 Python scanner 之间通过窄 JSON 参数契约传递这些选项。

主要入口：

- [`apps/openant-cli/cmd/scan.go`](apps/openant-cli/cmd/scan.go)
- [`libs/openant-core/core/scanner.py`](libs/openant-core/core/scanner.py)

## 3. 扫描初始化

扫描器拿到仓库后，先做以下工作：

1. 将仓库路径和输出路径转换为绝对路径。
2. 创建输出目录。
3. 清空本次扫描的 token、调用次数和成本统计。
4. 读取 LLM 配置。
5. 为 `app_context`、`enhance`、`analyze`、`verify`、`dynamic_test`、`report` 等阶段创建 `PhaseRegistry`。
6. 对每个阶段的 provider/model 做预检查，避免扫描到中途才发现模型不可用。
7. 创建 `ScanResult`，保存后续各阶段的路径、指标和状态。

阶段报告由 [`libs/openant-core/core/step_report.py`](libs/openant-core/core/step_report.py) 的 `step_context()` 自动记录。每个阶段通常会生成一个：

```text
<step>.report.json
```

## 4. 语言检测与源码解析

### 4.1 语言检测

`detect_language()` / `detect_languages()` 会遍历仓库中的受支持源码文件，按文件数量统计语言占比。

```text
Python 文件数：120
C/C++ 文件数：80
JavaScript 文件数：20
```

这里统计的是源码文件数量，不是代码行数。单语言入口会选择占比最高的语言；多语言扫描路径可以保留多个语言。

语言配置以 [`config/languages.json`](config/languages.json) 为准，扩展名、解析器、代码围栏和动态测试模板都从这里派生。

### 4.2 文件枚举

解析器枚举源码文件时会跳过：

- `.git`；
- `node_modules`；
- `build`、`dist`；
- `__pycache__`、虚拟环境；
- vendor、Pods 等依赖目录；
- 测试文件和测试目录，具体规则由语言解析器决定。

### 4.3 生成函数和方法记录

解析器使用 Tree-sitter 或语言对应的 AST 逻辑，从源码中提取：

- 函数和方法名称；
- 所在文件；
- 起止行号；
- 完整源码；
- 参数和返回值；
- 所属类；
- 可见性、导出信息和装饰器等元数据。

每个函数会生成唯一 ID，通常由仓库相对路径和函数标识组成；存在重载时还需要签名等信息避免碰撞。

主要入口：

- [`libs/openant-core/core/parser_adapter.py`](libs/openant-core/core/parser_adapter.py)
- `libs/openant-core/parsers/<language>/repository_scanner.py`
- `libs/openant-core/parsers/<language>/call_graph_builder.py`

典型输出包括：

```text
dataset.json
analyzer_output.json
scan_result.json 或 scan_results.json
```

其中：

- `analyzer_output.json` 更接近完整的函数数据库和索引；
- `dataset.json` 是下游分析使用的分析单元集合。

## 5. 调用图和反向调用图

### 5.1 调用图如何生成

以 C/C++ 为例，调用图构建器会重新解析函数体，查找类似 `call_expression` 的语法节点，提取调用目标名称，再把名称解析到函数索引中的具体函数 ID。

解析会综合使用：

- 同文件匹配；
- 类和接收者类型；
- 继承关系；
- include 和声明信息；
- 仓库内唯一匹配；
- 函数原型和签名；
- 标准库和无法解析目标的过滤规则。

解析不确定时通常不强行建立边，以免产生大量错误调用关系。

### 5.2 两个方向的图

正向调用图：

```text
caller -> callee
```

反向调用图：

```text
callee -> callers
```

例如：

```text
IpcHandler::onRequest -> Service::process
Service::process      -> FileWriter::write
```

正向图可以回答“当前函数调用了谁”；反向图可以回答“谁调用了当前函数”。两者通常同时保存到：

```text
call_graph.json
```

多语言扫描时可能按语言保存，并额外生成调用图索引。

## 6. 分析单元和有限深度上下文

OpenAnt 不只是把一个函数单独交给后续阶段，而是为目标函数拼装一个分析单元。

一个分析单元通常包含：

```text
主目标函数
  + 向下若干层：目标函数调用的函数
  + 向上若干层：调用目标函数的函数
```

“沿调用图展开一定深度”本质上是带 `visited` 集合的有限深度 BFS/图搜索，不是无限递归。

例如最大深度为 2：

```text
depth 0: Service::process
depth 1: FileWriter::write、IpcHandler::onRequest
depth 2: 更远的 caller/callee
```

循环边会通过 `visited` 去重，深度限制防止整个仓库被拼进一个 prompt。

最终上下文一般按以下顺序拼接：

```text
主目标函数
文件边界标记
被调用依赖
文件边界标记
调用者
```

这也解释了为什么后续模型既能看到危险操作，又能看到输入是从哪里来的。

## 7. 入口点识别与可达性过滤

### 7.1 入口点的含义

入口点不是简单的“调用图最顶层函数”，也不是只看“没有 caller 的函数”。

入口点表示攻击者或外部环境可能进入程序的边界，例如：

- `main`；
- 路由或控制器函数；
- 装饰器、路由属性标记的函数；
- 接收用户输入的函数；
- 语言或框架预定义的入口模式；
- 某些 native 或框架入口种子。

### 7.2 当前默认逻辑

当前主要是规则匹配，不是默认让大模型逐个判断。规则会检查函数名、装饰器、属性、函数体输入模式以及语言相关入口种子。

主要实现：

- [`libs/openant-core/utilities/agentic_enhancer/entry_point_detector.py`](libs/openant-core/utilities/agentic_enhancer/entry_point_detector.py)
- [`libs/openant-core/core/parser_adapter.py`](libs/openant-core/core/parser_adapter.py)

对 OpenHarmony 的 IPC、Ability、System Ability、Binder/RPC 等入口，当前通用规则可能不够，需要扩展专门的入口规则。

### 7.3 可达性计算

入口识别后，程序沿正向调用图从入口向下传播，保留能从入口到达的函数。

反向调用图的作用是反过来回答：

```text
某个函数是否能被某个入口调用到？
某个函数有哪些调用者？
```

可达性分析通常会给分析单元添加：

```text
reachable
is_entry_point
entry_point_reason
```

并在 `dataset.json` 的 metadata 中保存过滤统计。

如果没有识别到真实入口点，当前实现有安全保护：不会盲目把整个 dataset 清空，而是保留全部单元并记录警告。

实现和相关逻辑：

- [`libs/openant-core/utilities/agentic_enhancer/reachability_analyzer.py`](libs/openant-core/utilities/agentic_enhancer/reachability_analyzer.py)
- [`libs/openant-core/core/parser_adapter.py`](libs/openant-core/core/parser_adapter.py)

## 8. 应用上下文和威胁模型

应用上下文用于回答：

```text
这是什么应用？
攻击者是谁？
哪些接口对外暴露？
哪些操作属于安全边界？
什么情况才算漏洞？
```

### 8.1 优先读取威胁模型文件

扫描器会优先检查仓库中的：

```text
OPENANT.THREATMODEL.md
```

如果存在：

1. 读取并解析文件；
2. 校验 schema；
3. 转换为 `ApplicationContext`；
4. 记录 `context_source = threat_model`；
5. 记录原始文件 SHA-256 和警告。

恶意或格式错误的威胁模型不会被静默接受；格式错误通常会使上下文阶段失败。

### 8.2 没有文件时由 LLM 生成

如果没有威胁模型文件，程序收集：

- README、CLAUDE、AGENTS、SECURITY 等文档；
- pyproject、package.json、go.mod、Cargo.toml 等构建文件；
- 顶层和第二层目录结构；
- CLI、Web、Agent 等规则检测信号。

然后交给 `app_context` 阶段的大模型，要求返回结构化 JSON，经过解析、字段白名单和校验后写出：

```text
application_context.json
```

主要实现：

- [`libs/openant-core/context/application_context.py`](libs/openant-core/context/application_context.py)
- [`libs/openant-core/context/threat_model.py`](libs/openant-core/context/threat_model.py)

## 9. 可选的 LLM 可达性判断

如果开启 `--llm-reachability`，程序会在解析出全部分析单元后，按批次交给大模型复核。

每批默认约 25 个单元，投影信息包括：

```text
unit_id
unit_type
is_entry_point
reachable
截断后的代码
```

这不是每个函数单独调用一次，而是多个单元组成一个批次请求。启用后通常是所有解析单元进入批次复核，但具体输入受代码截断和批次大小限制。

LLM 只能补充或提升入口、外部输入、跨进程等信号，不能随意把规则已经确认的安全结论降级。应用后会重新执行可达性过滤。

实现：[`libs/openant-core/core/llm_reachability.py`](libs/openant-core/core/llm_reachability.py)。默认通常关闭。

## 10. Agent 增强阶段

增强阶段的输入是：

```text
reachable dataset
analyzer_output.json
repo_path
application_context
```

默认通常使用 agentic 模式，为每个分析单元创建一个上下文 Agent。Agent 可以多轮调用工具，直到认为上下文足够或达到最大迭代次数。

主要工具：

| 工具 | 作用 |
|---|---|
| `get_static_dependencies` | 查看静态分析得到的 caller/callee |
| `search_definitions` | 搜索函数或类的定义 |
| `search_usages` | 搜索某个函数在哪里被调用 |
| `read_function` | 读取指定函数完整源码 |
| `list_functions` | 查看文件中的函数列表 |
| `read_file_section` | 读取文件指定行区间 |
| `finish` | 提交本单元增强结果 |

Agent 的典型动作是：

```text
先读当前函数
  -> 搜索 caller/callee
  -> 找定义和使用位置
  -> 补读关键函数
  -> 形成数据流和安全边界说明
  -> finish
```

增强结果写入：

```text
agent_context
dataset_enhanced.json
```

如果增强失败，扫描通常继续使用未增强 dataset，并在 step report 中记录失败原因。

主要实现：

- [`libs/openant-core/core/enhancer.py`](libs/openant-core/core/enhancer.py)
- [`libs/openant-core/utilities/agentic_enhancer/agent.py`](libs/openant-core/utilities/agentic_enhancer/agent.py)
- [`libs/openant-core/utilities/agentic_enhancer/tools.py`](libs/openant-core/utilities/agentic_enhancer/tools.py)

## 11. Stage 1：漏洞检测

Stage 1 的核心函数是 `analyze_unit()`。它对分析 dataset 中的单元逐个进行漏洞判断；具体数量会受可达性过滤、`--limit`、解析错误和并发配置影响。

### 11.1 输入

每个单元通常提供：

- 主目标函数源码；
- 调用者和被调用者上下文；
- 文件名和位置信息；
- Agent 增强结果；
- 应用上下文；
- 入口点和可达性元数据。

### 11.2 Prompt

Prompt 位置：[`libs/openant-core/prompts/vulnerability_analysis.py`](libs/openant-core/prompts/vulnerability_analysis.py)。

核心要求包括：

```text
>>> ANALYZE THIS FUNCTION ONLY <<<
```

上下文函数用于理解数据流，但漏洞归属主要针对当前目标函数。模型需要给出：

- 是否 vulnerable、bypassable、inconclusive、protected 或 safe；
- 输入如何流向危险操作；
- 具体 sink；
- 攻击者能控制哪些数据；
- CWE、影响、推理和必要的复现信息。

### 11.3 输出

结果会通过 JSON 解析、必要时纠错，然后写入：

```text
results.json
```

分析阶段还会使用 checkpoint 支持恢复，并生成：

```text
analyze_checkpoints/
analyze.report.json
```

Stage 1 统计包括：

```text
vulnerable
bypassable
inconclusive
protected
safe
errors
```

主要实现：

- [`libs/openant-core/core/analyzer.py`](libs/openant-core/core/analyzer.py)
- [`libs/openant-core/prompts/vulnerability_analysis.py`](libs/openant-core/prompts/vulnerability_analysis.py)

## 12. Stage 2：攻击路径验证

Stage 2 是可选的攻击者模拟阶段。当前 `core/scanner.py` 的主扫描路径会先判断 Stage 1 是否存在 `vulnerable` 或 `bypassable` 候选；没有候选时跳过验证。

当前实现重点验证这些 Stage 1 候选，而不是默认对所有 safe/protected 单元重新扫描。

### 12.1 输入

验证器读取：

- `results.json`；
- `analyzer_output.json`；
- 应用上下文；
- 仓库路径；
- 函数索引和调用关系。

### 12.2 Agent 工具

Stage 2 的 `FindingVerifier` 当前主要使用：

```text
search_usages
search_definitions
read_function
list_functions
finish
```

增强阶段有的 `get_static_dependencies`、`read_file_section` 并不一定出现在 Stage 2 的工具定义中。

### 12.3 验证目标

模型需要模拟攻击者，尝试判断：

```text
是否存在可达入口
输入是否由攻击者控制
数据是否沿调用链流动
危险 sink 是否真正到达
路径在哪里断裂
攻击者在 sink 处拥有 full/partial/none 控制权
```

验证结果可能包含：

```text
agree
exploit_path
entry_point
data_flow
sink_reached
attacker_control_at_sink
path_broken_at
```

结果写入：

```text
results_verified.json
verify_checkpoints/
verify.report.json
```

### 12.4 重要状态规则

Stage 2 不完整不能自动当作安全：

```text
验证明确否定     -> 可以降级为安全方向
验证未完成/出错  -> 保留为 needs_review
```

扫描器会根据验证结果更新 vulnerable、safe、errors、needs_review 等指标。

主要实现：

- [`libs/openant-core/core/verifier.py`](libs/openant-core/core/verifier.py)
- [`libs/openant-core/utilities/finding_verifier.py`](libs/openant-core/utilities/finding_verifier.py)
- [`libs/openant-core/prompts/verification_prompts.py`](libs/openant-core/prompts/verification_prompts.py)

## 13. 构建 `pipeline_output.json`

这是一个确定性的 Python 转换步骤，不调用大模型。

函数位置：[`libs/openant-core/core/reporter.py`](libs/openant-core/core/reporter.py) 中的 `build_pipeline_output()`。

### 13.1 输入文件选择

扫描器维护 `active_results_path`：

```text
Stage 2 成功       -> results_verified.json
Stage 2 未启用/失败 -> results.json
```

### 13.2 漏洞筛选和转换

如果结果中有 `confirmed_findings`，优先使用它；否则从全部结果中按最终 `finding`/`verdict` 筛选：

```text
vulnerable
bypassable
```

然后将内部结果转换为统一结构：

```json
{
  "id": "VULN-001",
  "location": {
    "file": "src/service.cpp",
    "function": "Service::process"
  },
  "cwe_id": 78,
  "stage1_verdict": "vulnerable",
  "stage2_verdict": "confirmed",
  "description": "...",
  "vulnerable_code": "...",
  "impact": "...",
  "steps_to_reproduce": "..."
}
```

`stage2_verdict` 的常见映射：

```text
agree=True 且有 exploit_path -> confirmed
agree=True 但无 exploit_path -> agreed
verification.incomplete     -> unverified
Stage 2 明确否定            -> rejected
没有 Stage 2                 -> 保留 Stage 1 finding
```

顶层还会保存：

- 仓库信息；
- 分析日期；
- 应用类型；
- 威胁模型来源和哈希；
- 总单元、可达单元和分析单元数；
- 各阶段成本和耗时；
- vulnerable、safe、inconclusive、errors 统计；
- 跳过阶段和原因。

输出：

```text
pipeline_output.json
```

它是报告和动态测试共同使用的稳定桥接格式。它不是大模型直接生成的，但其中的描述、推理和 exploit path 可能来自此前的大模型结果。

## 14. 动态测试

动态测试是可选的 Docker 隔离执行阶段。

扫描器通常先判断：

```text
dynamic_test 已启用
且 Stage 1 存在候选
且 Docker 可用
```

否则记录跳过原因。

### 14.1 动态测试候选过滤

动态测试读取 `pipeline_output.json`，只接受：

```text
confirmed
agreed
vulnerable
```

定义在：[`libs/openant-core/core/verdict_taxonomy.py`](libs/openant-core/core/verdict_taxonomy.py) 的 `DYNAMIC_TESTABLE`。

因此当前实现中：

- 不是所有函数都动态测试；
- 不是所有 finding 都动态测试；
- `rejected`、`unverified`、`safe`、`protected`、`inconclusive` 不进入动态测试；
- 没有 Stage 2 时的 `bypassable` 也不在当前动态测试集合中。

### 14.2 语言和模板检查

程序优先根据 finding 自己的源文件扩展名确定语言，而不是盲目使用仓库主语言。

然后根据 `config/languages.json` 检查动态测试模板。C/C++ 当前配置为：

```json
"docker_template": null
```

所以 C/C++ finding 当前会被标记为 `SKIPPED`，不会浪费一次 LLM 测试生成调用。

### 14.3 LLM 生成测试材料

有模板后，`generate_test()` 为每个 finding 单独调用动态测试模型。

输入包括：

- 仓库名、语言和应用类型；
- finding ID、名称和 CWE；
- 漏洞位置；
- Stage 1/Stage 2 verdict；
- 漏洞描述、源码、影响和复现步骤；
- CWE 专属测试提示。

模型要求返回：

```json
{
  "dockerfile": "...",
  "test_script": "...",
  "test_filename": "test_exploit.py",
  "requirements": "...",
  "requirements_filename": "requirements.txt",
  "docker_compose": null,
  "needs_attacker_server": false
}
```

OpenAnt 会检查 JSON、必需字段和字符串类型。不合法时不会执行 Docker。

### 14.4 Docker 构建和执行

程序在临时目录中写入 Dockerfile、测试脚本、依赖文件和可选的攻击者服务器，然后：

```text
docker build
  -> docker run
```

单容器默认使用：

```text
无外部网络
512 MB 内存
1 个 CPU
256 个进程上限
cap-drop ALL
只读根文件系统
/tmp 和 /root 临时文件系统
no-new-privileges
```

多服务测试会使用 Docker Compose，并强制清理服务和卷。

动态测试执行器：

- [`libs/openant-core/core/dynamic_tester.py`](libs/openant-core/core/dynamic_tester.py)
- [`libs/openant-core/utilities/dynamic_tester/__init__.py`](libs/openant-core/utilities/dynamic_tester/__init__.py)
- [`libs/openant-core/utilities/dynamic_tester/docker_executor.py`](libs/openant-core/utilities/dynamic_tester/docker_executor.py)

一个需要注意的实现边界是：底层动态测试支持通过 `repo_path` 预置漏洞源文件，但当前 scanner 调用包装器时没有显式传入 `repo_path`。改造 OpenHarmony 动态测试时，需要核对这条参数链，避免 prompt 要求 `COPY` 源文件而构建上下文中实际没有该文件。

### 14.5 输出解析和重试

测试脚本必须向 stdout 输出：

```json
{
  "status": "CONFIRMED|NOT_REPRODUCED|BLOCKED|INCONCLUSIVE|ERROR",
  "details": "...",
  "evidence": []
}
```

结果解析器将 Docker 原始结果转换为 `DynamicTestResult`：

```text
构建失败             -> ERROR
LLM 没有生成有效测试  -> ERROR
容器超时             -> INCONCLUSIVE
没有合法 JSON 输出    -> ERROR
脚本输出的合法状态    -> 使用该状态
```

当前程序主要验证状态枚举和字段格式，不会独立判断 `uid=0`、文件内容或网络捕获是否真的证明了漏洞。因此动态测试结果仍依赖测试脚本自身的判断。

如果是 Docker 构建或运行错误，程序会把错误反馈给模型重新生成，默认最多 3 次重试，即初始执行加最多 3 次重试。超时通常不重试。

每个 finding 完成后会保存 checkpoint：

```text
dynamic_test_checkpoints/
```

成功的 finding 恢复时直接跳过，之前 `ERROR` 的 finding 会重新尝试。

最终输出：

```text
dynamic_test_results.json
DYNAMIC_TEST_RESULTS.md
```

动态结果不会直接修改 `pipeline_output.json`。

## 15. 总结报告

总结报告生成器会：

1. 读取 `pipeline_output.json`；
2. 如果存在 `dynamic_test_results.json`，按 finding ID 在内存中合并 `dynamic_testing`；
3. 删除过大的源码、完整描述和复现步骤，构造压缩输入；
4. 调用 `report` 阶段大模型；
5. 按固定 Markdown 模板写出总结报告。

报告模型主要看到：

```text
仓库信息
扫描统计
漏洞名称、位置、CWE
Stage 1/Stage 2 verdict
动态测试状态和证据
影响
成本、耗时和跳过阶段
```

输出：

```text
report/SUMMARY_REPORT.md
```

总结报告是大模型生成的，但报告中的威胁模型来源提示等部分会由程序确定性插入，避免被输入数据中的指令覆盖。

## 16. 单漏洞披露文档

披露文档不是一份总览，而是每个符合披露条件的 finding 一份 Markdown 文件。

当前披露条件包括：

```text
confirmed
agreed
unverified
vulnerable
bypassable
error
```

`rejected`、`safe`、`protected`、`inconclusive` 不生成披露文档。

每个 finding 单独调用报告模型，并行生成，默认最多 8 个 worker。

模型负责生成：

- 漏洞摘要；
- 复现步骤；
- 影响；
- 建议修复；
- 验证方式。

模型不会重新生成漏洞源码片段。程序会把 `vulnerable_code_section` 确定性地插回文档，降低源码被模型改写或捏造的风险。

输出：

```text
report/disclosures/DISCLOSURE_01_<安全化名称>.md
```

主要实现：

- [`libs/openant-core/core/reporter.py`](libs/openant-core/core/reporter.py)
- [`libs/openant-core/report/generator.py`](libs/openant-core/report/generator.py)
- [`libs/openant-core/report/prompts/disclosure.txt`](libs/openant-core/report/prompts/disclosure.txt)

## 17. 最终扫描级报告

所有阶段结束后，扫描器根据每个 `<step>.report.json` 生成：

```text
scan.report.json
```

它是机器可读的扫描级遥测报告，记录：

- 总成本；
- 总耗时；
- 总输入和输出 token；
- 完成的阶段；
- 跳过的阶段和原因；
- 解析错误和降级状态；
- 多语言统计；
- 威胁模型来源、哈希和警告；
- dataset、results、pipeline output、summary、dynamic test 等产物路径。

终端还会打印 `SCAN COMPLETE` 摘要，但终端摘要不是主要持久化结果。

## 18. 输出目录结构

一次完整扫描的输出目录大致如下：

```text
output/
├── dataset.json
├── dataset_enhanced.json                 # 可选
├── analyzer_output.json
├── call_graph.json                       # 单语言时常见
├── call_graphs.json                      # 多语言索引时可能存在
├── application_context.json              # 可选或由上下文阶段生成
├── results.json
├── results_verified.json                 # 启用并完成 Stage 2 时存在
├── pipeline_output.json
├── dynamic_test_results.json             # 启用动态测试时存在
├── DYNAMIC_TEST_RESULTS.md              # 启用动态测试时存在
├── parse.report.json
├── app-context.report.json               # 可选
├── enhance.report.json                   # 可选
├── analyze.report.json
├── verify.report.json                    # 可选
├── build-output.report.json
├── dynamic-test.report.json              # 可选
├── report.report.json                    # 可选
├── scan.report.json
├── analyze_checkpoints/                  # 可选
├── verify_checkpoints/                  # 可选
├── dynamic_test_checkpoints/            # 可选
└── report/
    ├── SUMMARY_REPORT.md                # 可选
    └── disclosures/                      # 可选
        ├── DISCLOSURE_01_*.md
        └── DISCLOSURE_02_*.md
```

## 19. 最容易混淆的文件

| 文件 | 作用 | 是否由大模型直接生成 |
|---|---|---|
| `dataset.json` | 分析单元集合 | 否，解析器生成 |
| `analyzer_output.json` | 函数和索引数据库 | 否，解析器生成 |
| `call_graph.json` | 正向和反向调用图 | 否，静态分析生成 |
| `results.json` | Stage 1 分析结果 | 结果字段受 LLM 影响，文件由程序写出 |
| `results_verified.json` | Stage 2 验证结果 | 结果字段受 LLM 影响，文件由程序写出 |
| `pipeline_output.json` | 统一桥接格式 | 否，`build_pipeline_output()` 组装 |
| `dynamic_test_results.json` | Docker 动态测试结果 | 脚本状态受 LLM 生成测试影响，文件由程序写出 |
| `SUMMARY_REPORT.md` | 总结报告 | 是，报告阶段 LLM 生成 |
| `DISCLOSURE_*.md` | 单漏洞披露文档 | 是，报告阶段 LLM 生成，源码片段由程序插入 |
| `scan.report.json` | 全流程成本、状态和路径汇总 | 否，程序确定性汇总 |

## 20. 面向 OpenHarmony 改造时的重点

### 20.1 入口点规则

需要增加 OpenHarmony 特有入口，例如：

- Ability 生命周期入口；
- System Ability 注册和服务入口；
- IPC/Binder/RPC 请求处理函数；
- N-API、JS bridge、native callback；
- 权限检查和跨进程边界。

### 20.2 调用图解析

C/C++ 中的虚函数、宏、模板、函数指针、异步 callback 和跨文件类型推断可能使简单名称匹配失效。需要评估：

- 虚调用和继承关系；
- 函数指针和 callback 注册；
- IPC proxy/stub 关系；
- 宏展开后的真实调用；
- 异步任务队列和线程切换。

### 20.3 Source、sink 和边界

OpenHarmony 漏洞挖掘不能只复用 Web CWE 提示，还应建立：

```text
IPC 参数、Parcel、Intent、URI、Bundle、N-API 参数
        ↓
权限检查、身份校验、跨进程传递
        ↓
文件、命令、反序列化、路径、网络和敏感系统服务 sink
```

### 20.4 动态测试能力

当前 C/C++ 动态测试模板为空，OpenHarmony 需要单独设计：

- C/C++ 编译镜像；
- 最小化 mock System Ability 或 IPC 服务；
- Parcel/Message 构造器；
- 权限和 UID/GID 模拟；
- 崩溃、越权、敏感数据访问和命令执行证据采集。

### 20.5 大模型结果不能作为唯一证据

当前动态测试脚本可以自行输出 `CONFIRMED`。更强的 OpenHarmony 智能体应增加独立证据校验，例如：

- 检查命令执行 marker 是否由目标服务产生；
- 检查文件读取是否越过预期权限边界；
- 检查网络请求是否来自被测服务而不是测试脚本本身；
- 对 IPC 返回码、调用身份和审计日志进行交叉验证。

## 21. 一页速记

```text
1. repo_path 是扫描起点。
2. 解析器把源码变成函数索引和调用图。
3. 正向图找 callee，反向图找 caller。
4. 分析单元是主函数加有限深度上下文，不是无限递归。
5. 入口点默认主要靠规则，不是大模型逐个判断。
6. 可达性从入口沿调用图传播，并写入 dataset metadata。
7. 应用上下文来自威胁模型文件或 app_context LLM。
8. Enhance Agent 用工具补充数据流、调用者和定义。
9. Stage 1 逐分析单元检测漏洞，写 results.json。
10. Stage 2 模拟攻击者验证路径，写 results_verified.json。
11. build_pipeline_output() 是确定性转换，不调用 LLM。
12. 动态测试只处理有限 verdict，并为每个 finding 生成 Docker 测试。
13. 动态结果单独写 dynamic_test_results.json，不回写 pipeline_output.json。
14. 报告阶段在内存中合并动态结果，再生成总结和披露文档。
15. scan.report.json 汇总整个扫描的阶段状态、成本、耗时和产物路径。
```
