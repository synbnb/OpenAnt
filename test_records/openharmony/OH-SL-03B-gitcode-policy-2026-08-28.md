# OH-SL-03B：GitCode 仓库地址与版本安全校验测试记录

日期：2026-08-28
阶段：源码定位器 SL-03B：GitCode URL、remote 和 revision 确定性策略
代码目录：`VulnFounder/libs/vulnfounder-core`
对应提交：待本阶段验收后提交

## 1. 本阶段解决的问题

SL-03A 已经可以把 OpenGrok 返回的源码路径通过 Manifest 的最长前缀规则映射为：

- Manifest project 名称；
- remote.fetch；
- GitCode 仓库 URL；
- Manifest revision。

但旧逻辑还没有独立的 GitCode 安全闸门。仅仅得到一个字符串形式的 URL，不能证明它适合交给后续 clone worker。特别是以下输入不能被接受：

- 模型或外部响应生成的非 allowlist 主机、组织或仓库；
- `http`、凭据、query、fragment、显式端口或路径穿越；
- 与 Manifest project 不同名的“同组织仓库”；
- 未知、非法或来自 LLM/bundle fallback 的 revision；
- Manifest 映射未解决或目标 revision 不一致的结果。

本阶段仍然不执行网络请求和 Git clone，只生成可审计的策略结果。

## 2. 原项目逻辑与修改后逻辑

### 原逻辑（SL-03A 之前）

代码搜索结果可以被继续处理，但仓库地址和版本没有统一的 clone 前置判定。调用方如果只检查 URL 是否“看起来像 HTTPS”，容易把错误仓库、伪造组织或不一致版本交给后续步骤。

### 修改后逻辑

新增 `core/source_locator/repository_policy.py`：

1. `validate_gitcode_url` 校验仓库 URL 的 HTTPS、主机 allowlist、组织 allowlist、路径段、仓库名、凭据/query/fragment/端口和路径编码；
2. `validate_gitcode_remote` 校验 Manifest 的 `remote.fetch` 必须是同一 allowlist 下的组织根地址；
3. `validate_revision` 校验 Git ref 字符、长度、遍历片段和可信来源，并区分 `allowed`、`missing`、`version_mismatch`、`rejected`；
4. `validate_repository_mapping` 将 URL、remote、revision 和 Manifest 状态合并为一个 `RepositoryPolicyDecision`；
5. 只有 `decision.allowed == true`（也就是 `decision.can_clone == true`）时，未来的 RepositoryManager 才能进入 clone 门禁；
6. `observed_url` 可用于后续网络层提交重定向后的地址。规范化地址发生变化或不在同一 allowlist 时直接拒绝；
7. 所有结果都保留原因、警告、规范化字段和嵌套校验结果，可直接写入 JSON 审计产物。

策略层不把 LLM 的字符串当作授权信息。LLM 可以提出候选，但仓库和 revision 必须来自 Manifest、固定配置或用户确认。

## 3. 代表性案例

### 正常映射

输入路径：`base/startup/init/param_service.c`。
Manifest 映射：

```text
project       = startup_init
remote.fetch  = https://gitcode.com/openharmony
repo_url      = https://gitcode.com/openharmony/startup_init
revision      = OpenHarmony-6.1-LTS
```

结果：

```text
status     = allowed
can_clone  = true
```

同时保留“尚未执行拉取后验证”的 warning；这表示可以进入未来的 clone 门禁，不表示仓库已经被验证或已经拉取。

### 拒绝伪造地址

```text
https://evil.example/openharmony/startup_init
https://gitcode.com/other-org/startup_init
https://user:pass@gitcode.com/openharmony/startup_init
https://gitcode.com/openharmony/../startup_init
```

这些地址均返回 `status = rejected`，并保留对应中文原因。

### 版本不一致

Manifest revision 为 `OpenHarmony-6.1-LTS`，用户目标 revision 为 `OpenHarmony-5.0-LTS` 时：

```text
status     = version_mismatch
allowed    = false
```

系统不会静默替换目标版本，也不会进入 clone。

### 不可信来源

即使文本是合法的 `OpenHarmony-6.1-LTS`，只要映射来源标记为 `bundle_fallback` 或 `llm`，也会被拒绝。这样可以避免模型或不完整构建元数据绕过 Manifest/用户确认边界。

## 4. 实现文件

- `libs/vulnfounder-core/core/source_locator/repository_policy.py`
  - URL、remote、revision 和 mapping 四层策略；
  - `RepositoryPolicyDecision`、`GitCodeURLValidation`、`RevisionValidation`；
  - `RepositoryPolicy` 复用封装；
  - JSON 序列化和 clone 门禁属性。
- `libs/vulnfounder-core/core/source_locator/__init__.py`
  - 导出 SL-03B 公共接口。
- `libs/vulnfounder-core/tests/source_locator/test_repository_policy.py`
  - 正常 GitCode 映射、allowlist、凭据、路径、重定向、版本、来源和序列化测试。

## 5. 测试命令与结果

测试在项目虚拟环境 `.venv` 中执行。

### SL-03B 专项测试

```bash
cd VulnFounder/libs/vulnfounder-core
../../.venv/bin/ruff check \
  core/source_locator/repository_policy.py \
  core/source_locator/__init__.py \
  tests/source_locator/test_repository_policy.py
../../.venv/bin/pytest -q tests/source_locator/test_repository_policy.py
```

结果：

```text
All checks passed!
35 passed in 0.04s
```

### source-locator 回归测试

```bash
../../.venv/bin/pytest -q tests/source_locator
```

结果：

```text
128 passed in 0.08s
```

### 编译与差异检查

```bash
python -m compileall -q core/source_locator tests/source_locator
git diff --check
```

结果：通过，无输出错误。

### 全量 Python 回归的环境边界

```bash
../../.venv/bin/pytest -x -q --tb=short
```

结果：前 5 个测试通过后，在既有 `tests/conformance/test_F1_receiver_type_contract.py::test_go` 处停止。该测试直接调用系统 `go` 可执行文件，而当前环境没有安装/暴露 `go`，错误为：

```text
FileNotFoundError: [Errno 2] No such file or directory: 'go'
```

该失败发生在进入 source-locator 测试前，和本阶段新增代码无关；source-locator 专项及其 128 个回归测试均已通过。

## 6. 当前边界

- 本阶段没有访问 GitCode，也没有执行 `git clone`、`git ls-remote` 或重定向请求；
- `allowed` 只表示“满足进入后续 clone 阶段的确定性前置条件”，不表示仓库存在、revision 已存在或源码已经验证；
- 目标目录冲突、用户确认、参数数组 clone、clone 后 HEAD/文件/符号复核属于后续 SL-04；
- OpenGrok revision 与 Manifest revision 的在线比对不在本阶段，OpenGrok 未提供可信 revision 时只能记录 warning；
- URL allowlist 是安全边界，不负责判断源码业务语义；服务归属和客户端关联仍需后续证据分析与 Agentic Loop。

## 7. 结论

SL-03B 已将“映射出仓库字符串”提升为“通过 host/组织/路径/来源/版本联合校验的结构化策略结果”。正常的 OpenHarmony GitCode Manifest 映射可以进入下一阶段；错误 URL、伪造组织、非法 revision、版本冲突和未解决映射都会在 clone 前被阻断。
