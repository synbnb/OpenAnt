# WEB-03D：兼容浏览器 `Origin: null` 的同源请求测试记录

## 1. 问题现象

用户从本机 Web 页面提交 `POST /scan` 时收到：

```text
403 Forbidden
cross-origin request refused
```

浏览器实际请求头为：

```text
Host:           127.0.0.1:18080
Origin:         null
Sec-Fetch-Site: same-origin
```

请求目标和 Host 都是本机固定端口，且 Fetch Metadata 明确标记为 `same-origin`。

## 2. 修改前后逻辑

### 修改前

`sameOriginOK` 要求非空 `Origin` 必须解析为与 `r.Host` 完全相同的 HTTP(S) Origin。字面量 `null` 解析后没有 Host，因此被误判为跨源请求。

### 修改后

- 继续要求请求 Host 是本机回环地址；
- 继续拒绝 `Sec-Fetch-Site: cross-site` 和 `cross-origin`；
- 对 `Origin: null` 仅在 `Sec-Fetch-Site: same-origin` 时放行；
- `Origin: null` 缺少 Fetch Metadata，或 Fetch Metadata 表示跨站时，仍拒绝；
- 其他非本机 Origin 仍拒绝；
- CSRF token 校验没有改变。

## 3. 修改文件

- `apps/vulnfounder-cli/internal/server/server.go`
  - 在 `sameOriginOK` 中增加受限的 opaque-origin 兼容分支。
- `apps/vulnfounder-cli/internal/server/auth_test.go`
  - 增加 `null + same-origin` 放行、`null + cross-site` 拒绝和缺少 Fetch Metadata 拒绝测试。

## 4. 测试结果

### 4.1 Web server 专项测试

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./internal/server -count=1
```

结果：通过。

```text
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server 1.652s
```

### 4.2 全量 Go 回归

结果：通过。

```text
?  github.com/synbnb/vulnfounder/apps/vulnfounder-cli                 [no test files]
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/cmd
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/checkpoint
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/config
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/git
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/languages
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/models
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/output
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/python
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/report
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server
?  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/types [no test files]
?  github.com/synbnb/vulnfounder/apps/vulnfounder-cli/ui             [no test files]
```

### 4.3 真实 Web 请求头验证

使用 `web-03d` 二进制、固定地址 `http://127.0.0.1:18080`，提交与用户完全相同的请求头。为避免启动扫描，测试请求使用无效 platform，仅观察同源校验是否通过：

```text
NULL_SAME_ORIGIN (400, unsupported platform)
NULL_CROSS_SITE  (403, cross-origin request refused)
FOREIGN_ORIGIN   (403, cross-origin request refused)
```

结果：通过。`null + same-origin` 已越过同源保护并进入正常业务校验；跨站和外部 Origin 仍被拒绝。

### 4.4 构建版本

```text
openant web-03d
  Go:     go1.25.7
  Python: 3.14.5
```

## 5. 当前使用方式

Web 已用 `web-03d` 重启，固定地址为：

```text
http://127.0.0.1:18080/
```

用户需要从根页面重新加载后再点击 Scan；旧的 `/scan` 错误响应页面不能重复使用。

## 6. 结论

WEB-03D 完成。浏览器实际发送的 `Origin: null` 场景已兼容，同时保留回环 Host、Fetch Metadata 和 CSRF 多层防护。

