# WEB-03B：Web 仓库下拉选择测试记录

## 1. 阶段目标

在保留手动 Git URL/本地路径输入的前提下，为 Web 首页增加已注册项目和最近扫描仓库的下拉选择，并让后端通过不暴露真实路径的 opaque repository ID 解析选择结果。

本阶段不实现浏览器目录上传；上传属于后续 Web-03C。

## 2. 修改前后逻辑

### 修改前

- 页面只有一个 `repo` 文本框；
- 后端直接使用浏览器提交的 URL 或本地路径；
- Web 没有读取 `~/.openant/projects/` 中的项目注册信息；
- Web 没有仓库目录接口，也没有对“已保存仓库”进行服务端解析。

### 修改后

- 增加 `GET /repositories` 仓库目录接口；
- 目录来源为：
  - `~/.openant/projects/` 中已初始化且仍可用的项目；
  - Web 最近扫描记录中的仓库；
- 页面增加 `Saved repository` 下拉框；
- 选择项只提交 opaque `repo_id`，真实路径/URL仅在服务端目录中解析；
- 如果 `repo_id` 无效或已过期，后端返回 400，不会回退使用同一请求中被篡改的 `repo` 字段；
- 未选择保存项时，继续使用原来的手动 URL/本地路径流程；
- 含有 HTTP(S) 用户名/密码的仓库 URL不会进入目录；
- 本地项目路径必须是当前存在的目录；
- 目录 ID 使用仓库身份的 SHA-256 摘要，不包含路径、URL 或凭据。

## 3. 修改文件

- `apps/vulnfounder-cli/internal/server/server.go`
  - 增加仓库目录构建、opaque ID、目录接口和 `repo_id` 解析；
  - 保留手动 `repo` 输入兼容逻辑。
- `apps/vulnfounder-cli/internal/server/repository_test.go`
  - 覆盖项目/最近扫描目录、凭据 URL 过滤、opaque ID、非法 ID 和 ID 优先解析。
- `apps/vulnfounder-cli/ui/index.html`
  - 增加保存仓库下拉框、隐藏 `repo_id` 字段和前端同步逻辑。

## 4. 测试环境

| 项目 | 值 |
|---|---|
| 系统 | macOS arm64 |
| Go | 项目内 `.devtools/go1.25.7` |
| Node.js | 系统 Node.js |
| 模块 | `apps/vulnfounder-cli` |
| Web 配置 | `/private/tmp/openant-live-llm` |

## 5. 测试命令与结果

### 5.1 Web server 专项测试

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./internal/server -count=1
```

结果：通过。

```text
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server  1.582s
```

覆盖内容：

- `/repositories` 返回已初始化项目和最近扫描仓库；
- 含凭据的项目 URL不会进入响应；
- 返回的 ID 不含路径分隔符、冒号或用户信息；
- 有效 ID能解析到服务端登记的目录；
- 未知 ID返回 400且不创建扫描任务；
- 有效 ID优先于被篡改的自由文本路径。

### 5.2 Web UI JavaScript 和静态契约检查

```bash
python3 -c 'from pathlib import Path; import re; s=Path("apps/vulnfounder-cli/ui/index.html").read_text(); print(re.search(r"<script>(.*?)</script>", s, re.S).group(1))' | node --check
python3 -c 'from pathlib import Path; s=Path("apps/vulnfounder-cli/ui/index.html").read_text(); checks={"repo_select": "id=\"repo-choice\"" in s, "opaque_field": "name=\"repo_id\"" in s, "sync_logic": "syncRepositoryChoice" in s, "custom_fallback": "Custom URL or local path" in s}; assert all(checks.values()), checks; print("WEB_03B_UI_STATIC_OK", " ".join(f"{k}={int(v)}" for k,v in checks.items()))'
```

结果：通过。

```text
WEB_03B_UI_STATIC_OK repo_select=1 opaque_field=1 sync_logic=1 custom_fallback=1
```

### 5.3 全量 Go 回归

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./... -count=1
```

结果：通过。

```text
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/cmd
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/checkpoint
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/config
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/git
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/languages
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/models
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/output
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/python
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/report
ok  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server
```

### 5.4 二进制构建和真实页面检查

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go build \
  -ldflags "-X github.com/synbnb/vulnfounder/apps/vulnfounder-cli/cmd.version=web-03b" \
  -o bin/openant ./main.go
./bin/openant version
```

结果：构建通过。

```text
openant web-03b
  Go:     go1.25.7
  Python: 3.14.5
```

当前真实 Web 地址：

```text
http://127.0.0.1:51129
```

接口检查：

```text
GET /repositories
{"repositories":[]}
```

当前环境没有已初始化项目和最近扫描记录，因此下拉框暂时只有：

```text
Custom URL or local path
```

首页已确认包含：

```text
Saved repository
repo-choice
repo_id
syncRepositoryChoice
```

### 5.5 变更格式检查

```bash
git diff --check
```

结果：通过。

## 6. 目录范围说明

本阶段下拉框读取的是 VulnFounder 项目注册目录和 Web 扫描历史，不会自动递归扫描：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code
```

因此该目录中的 OpenHarmony 子仓库目前不会自动出现。后续可以增加专门的“仓库根目录发现”阶段，让它枚举该目录下的一级 Git 仓库；这与浏览器上传仓库同样不属于本阶段。

## 7. 当前服务状态

Web 服务已使用 `web-03b` 二进制重新启动，当前地址为 `http://127.0.0.1:51129`，原有输出目录保留。

## 8. 结论

Web-03B 完成。用户现在可以从服务端登记的项目和最近扫描记录中选择仓库，同时保留原有手动输入路径/URL的能力。上传仓库和 OpenHarmony 根目录自动发现留到后续阶段。
