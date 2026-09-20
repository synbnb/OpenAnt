# OH-SL-04A：RepositoryManager 安全拉取测试记录

日期：2026-08-28
阶段：源码定位器 SL-04A：确认门禁、目录边界与安全 Git 拉取
代码目录：`VulnFounder/libs/vulnfounder-core`
对应提交：待本阶段验收后提交

## 1. 本阶段解决的问题

SL-03B 已经能判断 Manifest 映射得到的 GitCode URL 和 revision 是否满足安全策略，但项目此前没有一个与该策略连接的仓库管理器。旧的 Web/Go 流程主要面向用户直接输入 URL 的临时扫描：

- 没有使用 Manifest 映射结果作为 clone 的硬门禁；
- 没有要求一个范围明确的用户确认对象；
- 不能把仓库安全地放入项目级 `source_code_base`；
- 目标目录已存在时缺少“同源同版本复用、不同源不覆盖”的统一处理；
- 定位器没有结构化记录拉取命令和结果。

本阶段只实现“确认后的安全拉取/复用”，不做拉取后源码证据验证，也不生成 `SourceHandoff`。

## 2. 原项目逻辑与修改后逻辑

### 原逻辑

Go 侧已有 `cloneRepo`，可以为一个扫描任务临时执行浅克隆，并有部分 SSRF/重定向防护。但它属于旧扫描入口，接收的是扫描任务中的仓库字符串，不理解 SL-03A/SL-03B 的 Manifest project、目标 revision 和用户确认状态。

### 修改后逻辑

新增 `core/source_locator/repository_manager.py`，执行顺序如下：

1. 接收 `RepositoryMapping`，用 `RepositoryPolicy` 再校验一次 URL、remote、来源和 revision；
2. 没有 `RepositoryConfirmation`、确认未接受或确认的项目/URL/revision 与策略结果不完全一致时，立即返回 `rejected`，不执行任何 Git 命令；
3. 将 `GitCodeConfig.destination_root` 解析为项目根目录内的路径，默认是 `VulnFounder/source_code_base`；
4. 拒绝绝对路径、越界路径和任意一级符号链接；
5. 目标项目目录已存在时，只读检查 Git 工作树、origin 和目标 revision：完全一致则 `reused`，否则 `conflict`，不覆盖用户文件；
6. 新目录使用临时 staging 路径，执行浅克隆、目标 revision fetch、读取 `FETCH_HEAD`、分离 checkout 和 HEAD 比对；
7. 所有 Git 命令以参数数组调用，固定关闭 ext/file 协议和 HTTP 自动重定向，不经过 shell，不递归拉取 submodule；
8. 成功后将 staging 目录移动到目标目录，失败或冲突只清理本阶段自己创建的 staging 路径；
9. 输出 `RepositoryAcquisitionResult`，包括状态、目标目录、确认对象、命令摘要、原因和 warning，可直接写入 JSON。

## 3. 确认对象

`RepositoryConfirmation` 将用户批准绑定到三元组：

```text
project_name  = startup_init
canonical_url = https://gitcode.com/openharmony/startup_init
revision      = OpenHarmony-6.1-LTS
accepted      = true
```

因此，用户确认了仓库 A 后，不能被调用方替换成仓库 B 或另一个 revision。`accepted` 默认值为 `false`，避免调用方忘记显式确认。

## 4. 代表性案例

### 正常首次拉取

对 `base/startup/init/param_service.c` 的 Manifest 映射通过 SL-03B 后，用户确认 `startup_init`。RepositoryManager 在项目内创建：

```text
VulnFounder/source_code_base/startup_init/
```

结果为：

```text
status    = cloned
succeeded = true
```

### 重复执行

如果上述目录已存在，且 origin 指向同一个 GitCode 仓库、HEAD 与 `OpenHarmony-6.1-LTS` 对应 commit 一致，则不重新拉取，返回 `reused`。

### 目录冲突

如果目录是普通用户目录、缺少 origin、origin 指向另一个仓库，或 HEAD 与目标 revision 不一致，则返回 `conflict`。原有文件保持不变，不执行 clone，也不删除目录。

### 未确认或确认范围不一致

```text
没有 confirmation       → rejected，Git 调用数为 0
accepted = false        → rejected，Git 调用数为 0
revision 不一致         → rejected，Git 调用数为 0
```

### 符号链接

`source_code_base` 或 `source_code_base/startup_init` 是符号链接时，管理器在执行 Git 前拒绝，即使符号链接目标仍位于项目目录内也不自动跟随，避免目录边界语义不清。

## 5. 实现文件

- `libs/vulnfounder-core/core/source_locator/repository_manager.py`
  - `RepositoryConfirmation`：显式用户批准对象；
  - `RepositoryManager`：策略复核、目录边界、冲突检测和安全 Git 命令；
  - `CommandResult`/`CommandRecord`：可注入的命令执行适配器与有界审计记录；
  - `RepositoryAcquisitionResult`：`cloned`/`reused`/`conflict`/`rejected`/`failed` 结果。
- `libs/vulnfounder-core/core/source_locator/__init__.py`
  - 导出 SL-04A 公共接口。
- `libs/vulnfounder-core/tests/source_locator/test_repository_manager.py`
  - 使用完全可控的脚本化 runner，不启动真实 Git 进程。

## 6. 测试命令与结果

测试在项目虚拟环境 `.venv` 中执行。

### SL-04A 专项及 source-locator 回归

```bash
cd VulnFounder/libs/vulnfounder-core
../../.venv/bin/pytest -q tests/source_locator/test_repository_manager.py
../../.venv/bin/pytest -q tests/source_locator
```

结果：

```text
15 passed in 0.05s
143 passed in 0.09s
```

覆盖内容包括：

- 无确认、拒绝确认和确认字段篡改；
- 策略二次校验；
- 固定 Git 选项和参数数组；
- clone 失败及 staging 清理；
- 同源同版本复用；
- 非 Git、错误 origin、错误 revision 冲突保护；
- 目标根目录/仓库目录符号链接；
- 目标目录并发出现；
- 结果序列化和命令输出长度限制。

### 静态检查与编译

```bash
../../.venv/bin/ruff check \
  core/source_locator \
  tests/source_locator
python -m compileall -q core/source_locator tests/source_locator
git diff --check
```

结果：

```text
All checks passed!
编译通过；diff 无空白错误。
```

## 7. 当前边界

- 测试 runner 是脚本化适配器，本阶段没有访问 GitCode 真实网络；
- 没有修改现有 Go `cloneRepo`，也没有把定位器接入 Web/扫描入口；这属于后续桥接阶段；
- `cloned` 只表示 Git 拉取、目标 revision checkout 和 HEAD 比对完成，不表示目标文件、符号和 socket 证据存在；
- 拉取后文件/符号/remote/HEAD 的完整验证和 `SourceHandoff` 属于 SL-04B；
- 目录竞争在单进程安全检查范围内通过“出现即冲突”处理；跨进程长期锁和持久化 session 属于后续状态机；
- 当前 Git 命令输出采用有界捕获，磁盘总量限制、网络带宽限制和 post-clone 内容大小限制仍需后续阶段补充。

## 8. 结论

SL-04A 已把“用户确认的 Manifest 映射”连接到一个不覆盖用户数据的项目级仓库管理器。未确认、策略不通过、目录越界和仓库冲突都会在 Git 拉取前阻断；正常映射可以安全地浅拉取到 `source_code_base`，并留下可审计的命令与结果记录。
