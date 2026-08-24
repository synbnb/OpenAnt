# OH-DYN-13：Claude Code 动态测试任务包模式

## 1. 目标

为动态测试增加第二种运行模式：不使用 Docker，也不由 OpenAnt 内部 LLM 生成或执行载荷，而是生成一个可直接交给 Claude Code 的任务工作区。

本阶段只验证任务包的目录合同和上下文完整性，不启动真实 Claude Code，不连接开发板，不把任务包生成误认为漏洞验证。

## 2. 原逻辑与新逻辑

### 原逻辑

```text
pipeline_output.json
  → OpenAnt 内部 LLM 生成 Docker 测试
  → Docker build/run
  → dynamic_test_results.json
```

### 新逻辑

```text
pipeline_output.json + 静态产物 + source_code
  → ClaudeCodeTaskBuilder
  → <run-root>/task/
       context/、source_code、CLAUDE.md、Skill、results/
  → <run-root>/openharmony-public-tools/
       hdc、hvigorw、node、hap-sign-tool.jar 链接和说明
  → 用户在 task/ 中启动 Claude Code
```

Docker 模式仍然保留，并且是默认模式；Claude Code 模式通过 `--mode claude-code` 显式选择。

## 3. 实现内容

- 新增 `utilities/dynamic_tester/claude_code.py`；
- 新增 `.claude/skills/openant-openharmony-dynamic/SKILL.md` 模板；
- 新增 `CLAUDE.md`、`TASK.md` 和公开工具库说明模板；
- 只选择 `DYNAMIC_TESTABLE` 中的 `stage2_verdict` 候选；
- 复制完整 `pipeline_output.json` 和扫描目录中的静态 JSON/JSONL/Markdown/日志产物；
- 排除上一次 `dynamic_test` 结果，避免旧结论污染新任务；
- 建立 `task/source_code` 到真实源码目录的相对链接，并保存绝对路径元数据；
- 公开项目内工具链路径，但不复制 `.p12`、私钥、密码或 API key；
- 扩展 Python/Go CLI 的 `--mode docker|claude-code`；
- Claude Code 模式不检查 Docker，不要求 OpenAnt 动态测试 API key；
- 全扫描支持 `--dynamic-test-mode claude-code`，默认 Docker 行为保持不变。

## 4. 任务包结构

```text
<output>/run-*/
├── task/
│   ├── CLAUDE.md
│   ├── TASK.md
│   ├── task_manifest.json
│   ├── context/
│   │   ├── pipeline_output.json
│   │   ├── candidate_manifest.json
│   │   ├── artifact_manifest.json
│   │   ├── source_code.json
│   │   └── static_artifacts/
│   ├── source_code -> <source repository>
│   ├── .claude/skills/openant-openharmony-dynamic/SKILL.md
│   └── results/summary.json
└── openharmony-public-tools/
    ├── README.zh-CN.md
    ├── toolchain-manifest.json
    └── bin/
        ├── hdc
        ├── hvigorw
        ├── node
        └── hap-sign-tool.jar
```

## 5. 自动化测试

执行命令：

```text
PYTHONPATH=libs/openant-core python -m pytest -q \
  libs/openant-core/tests/test_claude_code_task.py \
  libs/openant-core/tests/test_scanner.py \
  libs/openant-core/tests/test_dynamic_tester_language.py
```

结果：

```text
41 passed in 0.33s
```

扩展回归（加入 Docker 脚手架和多语言关键回归）结果为 `72 passed in 0.38s`。

额外验证：

- `python -m py_compile` 通过核心动态测试、扫描器、Python CLI 和任务生成器；
- `python -m openant dynamic-test --help` 展示 `--mode {docker,claude-code}` 和 `--repo-path`；
- `python -m openant scan --help` 展示 `--dynamic-test-mode {docker,claude-code}`；
- 合成 pipeline 中 `confirmed` 候选被保留，`rejected` 候选被排除；
- `source_code` 链接、候选清单、静态产物、Skill、工具清单和初始结果文件均生成；
- 即使主机没有 Docker，Claude Code 模式仍能生成任务包；
- 旧 `dynamic_test_results.json` 不会被复制为当前任务的静态上下文。
- 当 `--output` 位于扫描目录内部时，任务输出目录也不会被递归复制为静态上下文。

使用实际的 `sensors_medical_sensor` 扫描产物再次生成任务包：

```text
/private/tmp/openant-claude-code-task-test-2/run-20260824T101223Z-d5fafadc/task/
```

结果：候选 2 个、静态产物 207 个、项目内 HDC/Hvigor/Node/签名工具链接均存在；OpenAnt 未启动 Claude Code，也未连接设备，因此这次记录只证明任务包准备正确，不代表动态漏洞结论。

项目内提供 `.devtools/go1.25.7/go/bin/go` 和 `gofmt`，本阶段已用该 `gofmt` 格式化 Go 修改；尝试执行 Go 测试时，当前沙箱没有 Go 模块缓存且无法访问 `proxy.golang.org`，因此依赖下载失败，未完成 Go 编译测试。网络和依赖可用的交付环境应运行：

```text
cd apps/openant-cli && gofmt -w cmd/dynamictest.go cmd/dynamictest_test.go internal/output/formatter.go
cd apps/openant-cli && go test ./...
```

## 6. 使用方式

```bash
./apps/openant-cli/bin/openant dynamic-test \
  /path/to/scan/pipeline_output.json \
  --mode claude-code \
  --repo-path /path/to/source_code \
  --output /path/to/claude-code-runs
```

命令完成后进入输出中的 `task/`，执行 `TASK.md` 里的启动命令：

```bash
cd <run-root>/task
claude --dangerously-skip-permissions
```

本阶段 Claude Code 负责把结论和证据写入 `task/results/`；OpenAnt 尚未实现结果摄取和自动合并到 `dynamic_test_results.json`。

## 7. 限制

- Claude Code 模式是用户信任的外部 Agent，不具备 Docker 容器隔离；只应针对已授权开发板和源码目录运行；
- 项目内 Command Line Tools 目录若未随交付包提供，任务只能生成，不能完成 HAP 构建或 HDC 交互；
- `source_code` 是真实仓库链接，不是只读副本；Skill 要求不要修改源码，但文件系统层面仍由用户负责保护；
- 任务包生成成功不代表 HAP 构建、签名、部署、系统服务调用或漏洞复现成功；这些必须由 Claude Code 结果和设备证据证明。
