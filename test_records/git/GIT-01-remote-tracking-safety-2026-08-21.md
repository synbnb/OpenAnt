# GIT-01 远程跟踪与推送安全配置记录

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | GIT-01：远程引用获取、分支跟踪与 upstream 推送保护 |
| 日期 | 2026-08-21 |
| 本地仓库 | `/Users/shiyu/学习/hyl/new/OpenAnt` |
| 操作前后 HEAD | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| 当前分支 | `master` |

## 2. 原逻辑与修改后逻辑

GIT-00 完成后的配置是：

```text
origin   -> https://github.com/synbnb/OpenAnt.git
upstream -> https://github.com/knostic/OpenAnt.git
master   -> upstream/master
```

存在两个问题：

1. `master` 仍跟踪原作者仓库的 `upstream/master`，默认 Git 操作可能选错远程。
2. `upstream` 的 push URL 仍等于原作者仓库地址，缺少本地误推保护。

本阶段调整为：

```text
origin fetch/push   -> https://github.com/synbnb/OpenAnt.git
upstream fetch      -> https://github.com/knostic/OpenAnt.git
upstream push       -> DISABLED
master tracks       -> origin/master
```

只更新远程跟踪引用和本地 Git 配置，不修改工作树，不移动本地 `master`，不进行 merge、rebase、commit 或 push。

## 3. 操作前预检

| 检查 | 结果 |
|---|---|
| HEAD | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| 分支 | `master` |
| 暂存区 | 空 |
| `branch.master.remote` | `upstream` |
| `upstream` push URL | `https://github.com/knostic/OpenAnt.git` |
| 本地 `upstream/master` | `2476527b9d6f929a5c987bd3d5df414da04f1eaf`（旧引用） |
| 本地 `origin/master` | 不存在 |

工作区已有内容与 GIT-00 记录一致，未在本阶段开始前清理、暂存或覆盖。

## 4. 获取远程引用

依次执行：

```bash
git fetch --prune origin
git fetch --prune upstream
```

结果：两条命令退出码均为 `0`。

- `origin/master` 新建并指向 `b5019628c301553f545a8bf5ba0963097e725723`。
- `upstream/master` 从 `2476527` 更新到 `b5019628c301553f545a8bf5ba0963097e725723`。
- `--prune` 清除了本地已失效的远程跟踪引用 `upstream/renovate/python-dotenv-1.x`；这是本地引用清理，没有删除 GitHub 远程分支。
- Fork 包含的其他远程分支仅被记录为 `origin/*` 跟踪引用，没有检出到工作区。

两个 fetch 均未使用 pull，也没有触发合并或变基。

## 5. Git 安全配置

执行：

```bash
git remote set-url --push upstream DISABLED
git branch --set-upstream-to=origin/master master
```

结果：退出码 `0`。

最终配置：

```text
origin   https://github.com/synbnb/OpenAnt.git (fetch)
origin   https://github.com/synbnb/OpenAnt.git (push)
upstream https://github.com/knostic/OpenAnt.git (fetch)
upstream DISABLED                              (push)
```

分支配置：

```text
branch.master.remote origin
branch.master.merge refs/heads/master
```

`DISABLED` 是本地无效推送目标，用于使常规 `git push upstream` 快速失败。它不能阻止用户绕过 remote、显式向完整原仓库 URL 推送，但可以防止日常误用 upstream 名称。

## 6. 独立验证结果

### 6.1 分支与引用

```text
HEAD              2476527b9d6f929a5c987bd3d5df414da04f1eaf
origin/master     b5019628c301553f545a8bf5ba0963097e725723
upstream/master   b5019628c301553f545a8bf5ba0963097e725723
```

`git branch -vv`：

```text
master 2476527 [origin/master: behind 2]
```

`git rev-list --left-right --count HEAD...origin/master`：

```text
0  2
```

说明本地 `master` 没有个人独有提交，仅落后个人 Fork 当前 `master` 两个提交。

### 6.2 工作区不变量

| 检查 | 结果 |
|---|---|
| HEAD 操作前后 | 完全一致 |
| 当前分支操作前后 | 均为 `master` |
| 暂存区 | 空 |
| merge 状态 | 不存在 |
| rebase 状态 | 不存在 |
| `git diff --check` | 退出码 `0` |
| 已有未提交文件 | 均保留 |

本阶段没有运行代码测试，因为没有修改源码、依赖或工作树内容；验证对象是 Git 引用、跟踪配置和工作区不变量。

### 6.3 推送行为

本阶段没有执行真实 push，也没有执行 push dry-run。推送安全通过以下只读配置结果验证：

```text
git remote get-url --push upstream -> DISABLED
branch.master.remote               -> origin
```

个人仓库的 push 权限已在 GIT-00 通过 GitHub API 验证为 `true`。

## 7. 阶段结论

GIT-01 已完成：两个远程跟踪引用已更新，`master` 已改为跟踪个人 Fork，`upstream` 常规推送路径已禁用。本地分支仍停留在原实施基线，工作区修改未受影响。

下一阶段需要单独协商：是先创建 OpenHarmony 功能分支保存当前工作，还是先处理本地 `master` 落后远程两个提交的问题。在用户批准前，不创建分支、不合并、不提交、不推送。
