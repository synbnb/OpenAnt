# OH-00E / WEB-03C：Web 使用项目内 OpenHarmony 源码库测试记录

## 1. 阶段目标

让 OpenAnt Web 直接发现项目内的 `source_code_base/`，从而在用户启动 Web 后可以从下拉框选择随项目保存的 OpenHarmony 仓库，不再依赖外部 `openharmony_reference` 目录或用户手工输入绝对路径。

本阶段一次性完成 Web 侧所需的源码根目录解析、仓库目录枚举、opaque ID 解析、兼容逻辑、页面提示和测试。扫描器、Python 解析器、调用图、LLM 流程和动态测试没有修改。

## 2. 修改前后逻辑

### 修改前

- Web `/repositories` 只读取 `~/.openant/projects/` 的项目登记和当前 Web 进程的最近扫描记录。
- 项目内的 `OpenAnt/source_code_base/` 不会自动出现在下拉框中。
- Web 只能依靠手工输入路径或 URL，项目打包后还需要额外告诉使用者源码在哪里。

### 修改后

- 增加可迁移的源码根目录解析器：
  - `OPENANT_SOURCE_CODE_BASE` 存在时使用显式目录；
  - 否则从当前工作目录和可执行文件目录向上查找 `source_code_base/`；
  - 不包含任何用户个人绝对路径，也不回退到旧的外部 OpenHarmony 目录。
- `/repositories` 新增 `source_code_base` 来源：只枚举该目录的一级子目录。
- 只有包含独立 `.git` 目录或 `.git` 文件的子目录才会进入目录；普通目录、一级符号链接和符号链接 `.git` 会被跳过。
- 浏览器只收到仓库名称、来源和 opaque `repo_id`，不收到真实本地路径；POST `/scan` 仍在服务端解析 ID。
- 已有 `~/.openant/projects/`、最近扫描记录和手工 URL/路径输入继续保留，不会因为新增项目内目录而被裁剪。

## 3. 修改文件

- `apps/openant-cli/internal/config/source_code_base.go`
  - 新增可移植的 `source_code_base` 路径解析。
- `apps/openant-cli/internal/config/source_code_base_test.go`
  - 覆盖显式环境变量、无效覆盖路径和工作目录祖先发现。
- `apps/openant-cli/internal/server/server.go`
  - 将项目内一级 Git 仓库加入 Web 目录，并过滤符号链接和非 Git 目录。
- `apps/openant-cli/internal/server/repository_test.go`
  - 增加项目内仓库目录、普通目录、子目录符号链接和 `.git` 符号链接测试。
- `apps/openant-cli/ui/index.html`
  - 更新仓库选择提示，说明项目内源码仓库来源；保留原有 opaque ID 和手动输入逻辑。
- `source_code_base/README.md`
  - 更新 Web 使用约定。

## 4. 专项测试结果

### 4.1 配置解析与 Web server 测试

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./internal/config ./internal/server -count=1
```

结果：通过。

```text
ok  github.com/knostic/open-ant-cli/internal/config  1.300s
ok  github.com/knostic/open-ant-cli/internal/server  1.793s
```

覆盖内容：

- 项目内源码根目录的显式覆盖和祖先目录发现；
- 缺失显式目录拒绝；
- 22 个仓库之外的普通目录不进入目录；
- 一级符号链接和符号链接 `.git` 不进入目录；
- 项目内仓库仍使用服务端 opaque ID解析；
- 原有项目目录、最近扫描和手工输入兼容测试继续通过。

### 4.2 Web UI 静态检查

```text
WEB_03C_UI_STATIC_OK project_source_hint=1 repository_select=1 opaque_field=1 sync_logic=1
```

页面脚本通过 Node.js 语法检查；下拉框、`repo_id` 隐藏字段、选择同步逻辑和项目内源码提示均存在。

### 4.3 全量 Go 回归

在当前沙箱内首次运行时，`cmd` 包的既有 `httptest.NewServer` 测试因 IPv6 回环监听权限被环境拒绝；没有出现代码断言失败。随后在允许本机回环监听的环境中重跑，结果全部通过：

```text
?  github.com/knostic/open-ant-cli  [no test files]
ok github.com/knostic/open-ant-cli/cmd
ok github.com/knostic/open-ant-cli/internal/checkpoint
ok github.com/knostic/open-ant-cli/internal/config
ok github.com/knostic/open-ant-cli/internal/git
ok github.com/knostic/open-ant-cli/internal/languages
ok github.com/knostic/open-ant-cli/internal/models
ok github.com/knostic/open-ant-cli/internal/output
ok github.com/knostic/open-ant-cli/internal/python
ok github.com/knostic/open-ant-cli/internal/report
ok github.com/knostic/open-ant-cli/internal/server
?  github.com/knostic/open-ant-cli/internal/types [no test files]
?  github.com/knostic/open-ant-cli/ui [no test files]
```

### 4.4 二进制构建

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go build \
  -ldflags "-X github.com/knostic/open-ant-cli/cmd.version=web-03c" \
  -o bin/openant ./main.go
./bin/openant version
```

结果：通过。

```text
openant web-03c
  Go:     go1.25.7
  Python: 3.14.5
```

### 4.5 真实 Web 接口和首页检查

使用 `web-03c` 二进制启动本地 Web 后：

```text
GET /repositories
REAL_WEB_REPOSITORIES_OK count=22 sources=['source_code_base']
REAL_WEB_INDEX_OK selector=1 opaque_field=1 source_option=1 project_local_hint=1
```

真实接口返回 22 个项目内仓库，来源全部为 `source_code_base`；首页确认存在仓库下拉框、opaque `repo_id` 字段和项目内源码提示。页面标签不包含真实 `source_code_base` 绝对路径。

## 5. 当前 Web 状态

当前运行的二进制版本为 `web-03c`，本地地址由系统动态分配。启动目录位于 OpenAnt 项目根目录，因此自动发现：

```text
OpenAnt/source_code_base/
```

也可以通过 `OPENANT_SOURCE_CODE_BASE=/path/to/source_code_base` 指定另一个项目源码根目录。

## 6. 范围边界

- 本阶段没有增加浏览器上传压缩包功能；现有项目内源码库选择和手动 URL/路径输入已经可以工作。若后续需要上传，需要单独设计压缩包解压、路径穿越、符号链接、磁盘配额和仓库生命周期策略。
- 本阶段没有把 22 个子仓库合并为外层 OpenAnt Git 仓库；每个子仓库仍保持独立 `.git` 和 `origin`。
- `~/.openant/projects/` 仍保存项目元数据和扫描输出，不会被 `source_code_base/` 替代。

## 7. 结论

OH-00E / WEB-03C 完成。Web 已能在可迁移的 OpenAnt 项目目录中发现并选择 22 个 OpenHarmony 仓库，opaque ID、路径过滤、旧目录兼容和真实页面验证均通过。

