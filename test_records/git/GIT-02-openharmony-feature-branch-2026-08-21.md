# GIT-02 OpenHarmony 功能分支创建记录

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | GIT-02：创建 OpenHarmony 本地功能分支 |
| 日期 | 2026-08-21 |
| 本地仓库 | `/Users/shiyu/学习/hyl/new/OpenAnt` |
| 操作前分支 | `master` |
| 操作后分支 | `feature/openharmony-adaptation` |
| 分支起点 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |

## 2. 原逻辑与修改后逻辑

操作前，OpenHarmony 相关未提交修改仍位于 `master` 工作区。`master` 跟踪个人 Fork 的 `origin/master`，但本地提交相对远程落后两个提交。

本阶段只建立独立工作分支：

```text
master                          -> 2476527
feature/openharmony-adaptation  -> 2476527
```

切换分支时保留当前索引和工作区，不执行 stash、commit、fetch、merge、rebase 或 push。

## 3. 分支冲突预检

本地检查：

```bash
git branch --list feature/openharmony-adaptation
git branch -r --list origin/feature/openharmony-adaptation upstream/feature/openharmony-adaptation
```

结果均为空。

远程实时检查：

```bash
git ls-remote --heads origin refs/heads/feature/openharmony-adaptation
git ls-remote --heads upstream refs/heads/feature/openharmony-adaptation
```

两条命令均退出码 `0` 且无输出，确认个人 Fork 和原作者仓库均不存在同名分支。

## 4. 操作前工作区基线

```text
HEAD:   2476527b9d6f929a5c987bd3d5df414da04f1eaf
branch: master
```

工作区：

```text
 M .gitignore
?? OPENANT_COMPLETE_PIPELINE_GUIDE.zh-CN.md
?? OPENHARMONY_ADAPTATION_IMPLEMENTATION_PLAN.zh-CN.md
?? libs/openant-core/tests/fixtures/openharmony/
?? libs/openant-core/tests/openharmony/
?? test_records/
```

暂存区为空，`git diff --check` 通过。

## 5. 分支创建

执行：

```bash
git switch -c feature/openharmony-adaptation
```

结果：退出码 `0`。

```text
Switched to a new branch 'feature/openharmony-adaptation'
```

该命令只创建本地分支引用并切换当前分支，没有在 GitHub 创建远程分支。

## 6. 独立验证结果

### 6.1 分支指针

```text
HEAD                            2476527b9d6f929a5c987bd3d5df414da04f1eaf
master                          2476527b9d6f929a5c987bd3d5df414da04f1eaf
feature/openharmony-adaptation  2476527b9d6f929a5c987bd3d5df414da04f1eaf
```

三个指针完全一致，创建分支没有移动提交基线。

新分支相对 `origin/master` 的提交计数：

```text
0  2
```

即新分支没有个人独有提交，仍落后远程两个提交。

### 6.2 工作区保护

切换后工作区清单与操作前逐项一致：

```text
 M .gitignore
?? OPENANT_COMPLETE_PIPELINE_GUIDE.zh-CN.md
?? OPENHARMONY_ADAPTATION_IMPLEMENTATION_PLAN.zh-CN.md
?? libs/openant-core/tests/fixtures/openharmony/
?? libs/openant-core/tests/openharmony/
?? test_records/
```

| 检查 | 结果 |
|---|---|
| 暂存区 | 空 |
| merge 状态 | 不存在 |
| rebase 状态 | 不存在 |
| `git diff --check` | 退出码 `0` |
| 文件清理、覆盖 | 未发生 |

### 6.3 跟踪与推送状态

新分支没有配置 `branch.feature/openharmony-adaptation.remote` 或 `merge`，因此没有 Git upstream，也没有默认远程推送目标。

本地出现以下编辑器元数据：

```text
branch.feature/openharmony-adaptation.vscode-merge-base origin/master
```

它只供 VS Code 计算分支比较基线，不是 Git upstream 配置，不会使分支自动推送或拉取。

本阶段没有执行任何 push，包括 dry-run。

## 7. 测试范围说明

本阶段没有修改源码、测试、依赖或工作树内容，因此没有重复运行代码测试。验证范围是：

- 分支名无本地或远程冲突。
- 分支指针不变。
- 工作区文件清单不变。
- 暂存区保持为空。
- 没有合并、变基或远程副作用。

## 8. 阶段结论

`feature/openharmony-adaptation` 已从原实施基线安全创建，当前 OpenHarmony 相关工作已与 `master` 分支身份隔离，所有未提交内容完整保留。

下一阶段应先审阅当前未提交文件的归属，制定原子提交拆分方案，并明确排除用户原有文档或其他不应提交的内容。在用户批准前，不暂存、不提交、不推送，也不处理落后的两个上游提交。
