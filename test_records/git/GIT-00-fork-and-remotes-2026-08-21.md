# GIT-00 个人 Fork 与双远程配置记录

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | GIT-00：个人 Fork 与 `origin`/`upstream` 配置 |
| 日期 | 2026-08-21 |
| 本地仓库 | `/Users/shiyu/学习/hyl/new/VulnFounder` |
| 操作前本地提交 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| 当前分支 | `master` |
| GitHub 账号 | `synbnb` |

## 2. 原逻辑与目标逻辑

操作前只有一个远程：

```text
origin -> https://github.com/knostic/VulnFounder.git
```

读取和推送均指向原作者仓库，本地账号通常无权向该仓库直接推送。

本阶段目标：

```text
origin   -> https://github.com/synbnb/VulnFounder.git
upstream -> https://github.com/knostic/VulnFounder.git
```

- `origin` 用于后续推送个人开发分支。
- `upstream` 用于获取原项目更新。
- 保留原项目提交历史，不重新执行 `git init`，不重新克隆。

## 3. 身份与权限验证

实际 GitHub API 身份请求成功：

```text
login: synbnb
name: NJUsy
```

联网状态下 `gh auth status` 成功，Git 协议为 HTTPS，授权范围包含 `repo` 和 `workflow`。记录中不保存 token。

## 4. Fork 创建

创建前只读查询结果：

- `knostic/VulnFounder` 存在，是公开的非 Fork 仓库，默认分支为 `master`。
- `synbnb/VulnFounder` 返回 HTTP 404，说明个人仓库当时不存在。

第一次尝试：

```bash
gh repo fork knostic/VulnFounder --clone=false --remote=false
```

当前 `gh 2.92.0` 在显式提供仓库参数时不支持 `--remote`，命令在参数解析阶段退出，未创建 Fork，也未修改本地 remote。

依据 CLI 帮助，省略 `--remote` 即不会添加本地 remote，随后执行：

```bash
gh repo fork knostic/VulnFounder --clone=false
```

结果：成功创建：

```text
https://github.com/synbnb/VulnFounder
```

GitHub API 复验：

| 字段 | 结果 |
|---|---|
| `fork` | `true` |
| `parent` | `knostic/VulnFounder` |
| `source` | `knostic/VulnFounder` |
| 默认分支 | `master` |
| 可见性 | public |
| 当前账号 `push` 权限 | `true` |
| 当前账号 `admin` 权限 | `true` |

## 5. 本地 remote 调整

执行：

```bash
git remote rename origin upstream
git remote add origin https://github.com/synbnb/VulnFounder.git
```

调整结果：

```text
origin   https://github.com/synbnb/VulnFounder.git (fetch/push)
upstream https://github.com/knostic/VulnFounder.git (fetch/push)
```

该操作只修改 `.git/config`，没有修改工作区文件、提交对象或当前分支内容。

## 6. 连接测试

使用 `git ls-remote --heads <remote> master` 分别读取两个远程，均成功：

```text
origin/master   b5019628c301553f545a8bf5ba0963097e725723
upstream/master b5019628c301553f545a8bf5ba0963097e725723
```

结论：

- 两个 HTTPS 远程均可读取。
- Fork 创建时与上游当前 `master` 一致。
- GitHub API 明确确认个人仓库具备推送权限。
- 本阶段没有执行真实 push，也没有使用会更新远端引用的测试操作。

## 7. 基线差异

本地 `HEAD` 仍为：

```text
2476527b9d6f929a5c987bd3d5df414da04f1eaf
```

远程 `master` 当前为：

```text
b5019628c301553f545a8bf5ba0963097e725723
```

GitHub Compare API 结果：远程提交相对本地基线 `ahead_by: 2`。当前本地 `upstream/master` 只是尚未 fetch 的旧远程跟踪引用，仍显示 `2476527`，因此不能用它代表远程实时状态。

本阶段没有 fetch、pull、merge 或 rebase，避免在存在未提交修改时擅自引入上游变更。

## 8. 已发现的跟踪分支问题

`git remote rename origin upstream` 会同步改写分支配置。当前状态是：

```text
branch.master.remote upstream
branch.master.merge refs/heads/master
```

也就是说，当前 `master` 仍跟踪 `upstream/master`。在修正前，不应执行不带远程参数的 `git push`，否则 Git 会尝试向原作者仓库推送。

建议下一小阶段经过用户确认后：

1. 获取两个远程的最新引用，但不合并。
2. 将本地 `master` 的跟踪目标改为 `origin/master`。
3. 为 OpenHarmony 工作建立独立开发分支，例如 `feature/openharmony-adaptation`。
4. 单独协商如何处理本地基线落后上游两个提交的问题。

## 9. 收尾审计中的命令书写事件

收尾审计原计划使用 `rg` 检查本记录中的关键文本，但搜索参数里的 Markdown 反引号被 shell 解释为命令替换，意外触发了一次不带参数的 `git push` 尝试。

该命令运行在禁止外网 DNS 的受限环境中，在建立 GitHub 连接前即失败：

```text
fatal: unable to access 'https://github.com/knostic/VulnFounder.git/':
Could not resolve host: github.com
```

因此没有连接远程、没有上传对象、没有更新远程引用。随后在联网只读权限下重新执行：

```bash
git ls-remote --heads origin master
git ls-remote --heads upstream master
```

两个远程仍与事件前完全一致：

```text
origin/master   b5019628c301553f545a8bf5ba0963097e725723
upstream/master b5019628c301553f545a8bf5ba0963097e725723
```

结论：这是一次未建立网络连接的本地命令尝试，未造成远程状态变化。后续 shell 文本搜索使用不可执行的安全引用方式，避免在命令参数中留下可被 shell 展开的反引号。

## 10. 工作区保护

操作前后本地 `HEAD` 与当前分支没有变化。已有未提交内容均保留，包括：

- `.gitignore` 的项目本地工具链忽略规则。
- OpenHarmony 实施计划。
- OH-00A 语料清单测试与 fixture。
- 环境和阶段测试记录。
- 用户原有的 `OPENANT_COMPLETE_PIPELINE_GUIDE.zh-CN.md`。

本阶段未提交、未暂存、未推送、未清理或覆盖任何上述文件。

## 11. 阶段结论

个人 Fork 已成功创建，`origin` 与 `upstream` 双远程已按目标配置，远程读取和个人仓库权限验证通过。

由于 Git 自动保留了 `master -> upstream/master` 的跟踪关系，默认推送目标尚不符合预期。为遵守逐阶段协商门禁，本阶段不擅自修改分支跟踪关系；用户审阅并批准下一小阶段前，不执行 fetch、同步、分支创建、提交或推送。
