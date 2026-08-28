# OH-SL-01 OpenGrok 实例与 REST API 实测记录

日期：2026-08-28  
阶段：OpenHarmony 源码定位前置环节（只读联通性与能力验证）  
测试对象：用户提供的 OpenGrok 实例  
测试目的：确认实例是否可以被工具调用，并根据真实响应决定源码定位工具的接口组合。

## 1. 测试范围与安全边界

本轮只执行 HTTPS `GET` 请求，没有提交任何配置、索引、项目或 suggester 修改请求，也没有尝试猜测或读取凭据。测试过程中不保存 Cookie，不记录 Authorization 信息。

测试基址：

```text
https://u375886-9ad1-ba9448df.westc.seetacloud.com:8443/source
```

OpenAPI 文件：`/Users/shiyu/学习/hyl/new/openapi.yaml`。

## 2. 实例基本信息

| 检查项 | 实测结果 | 结论 |
| --- | --- | --- |
| HTTPS/TLS | 证书校验通过 | 可以作为 HTTPS 上游 |
| 网页根路径 `/source/` | HTTP 200 | Web 应用在线 |
| OpenGrok 版本 | 页面标记为 `1.14.11`，构建标识为 `512e738c6819518f2a95b9f49a3ea8550efff948` | 不是假设的旧版接口，需按 1.14 行为适配 |
| 默认项目 | 页面 Cookie/下拉框显示 `openharmony` | 工具仍应显式传 `projects=openharmony`，不能依赖 Cookie |
| 上下文路径 | 页面使用 `/source` | REST 完整前缀是 `/source/api/v1`，不是主机根下的 `/api/v1` |
| 浏览器跨域头 | 搜索和 raw 响应均未看到 `Access-Control-Allow-Origin` | 由 OpenAnt 后端代理，不能让浏览器直接调用该实例 |

## 3. REST API 端点矩阵

无 Bearer token 的真实结果如下。这里的“受保护”是该实例的行为，不代表所有 OpenGrok 部署都一定相同。

| 端点 | 方法 | 状态 | 实际用途/判断 |
| --- | --- | --- | --- |
| `/source/api/v1/` | GET | 401 | API 根目录受保护，不能用它判断单个端点是否可用 |
| `/source/api/v1/system/ping` | GET | 200 | 可用于健康检查 |
| `/source/api/v1/system/indextime` | GET | 200 | 返回 `2026-04-09T10:21:31.737+00:00`；应展示为索引时间并提示可能陈旧 |
| `/source/api/v1/suggest/config` | GET | 200 | suggester 开启，最大结果 10，支持 `defs/path/hist/refs/type/full` 字段 |
| `/source/api/v1/search` | GET | 200 | 无 token 可检索；支持 `def`、`symbol`、`full`、`path`、`type`、`projects`、`maxresults`、`start`、`maxhitsperfile`、`sort` |
| `/source/api/v1/history` | GET | 204 | 本次选择的路径没有返回历史内容；端点可达但不能假设一定有记录 |
| `/source/api/v1/file/content` | GET | 401 | 文档定义的源码内容接口在此实例需要 token |
| `/source/api/v1/file/genre` | GET | 401 | 需要 token |
| `/source/api/v1/file/defs` | GET | 401 | 需要 token |
| `/source/api/v1/list` | GET | 401 | 需要 token |
| `/source/api/v1/projects`、`/indexed` | GET | 401 | 项目元数据需要 token |
| `/source/api/v1/projects/openharmony/files` | GET | 401 | 文件清单需要 token |
| `/source/api/v1/projects/openharmony/repositories` | GET | 401 | 仓库清单需要 token |
| `/source/api/v1/system/version` | GET | 401 | 版本 REST 端点需要 token；网页标记可作为只读回退信息 |
| `/source/raw/<path>` | GET | 200 | 网页路由可直接返回纯文本源码；该路由不在提供的 OpenAPI 中 |
| `/source/xref/<path>` | GET | 200 | 返回带行号/符号链接的 HTML 交叉引用页面；可做可选回退，不作为主解析输入 |
| `/source/download/<path>` | GET | 200 | 返回附件下载，`Content-Disposition` 为 attachment；工具不应优先使用 |

## 4. 真实 OpenHarmony 搜索样例

### 4.1 精确函数定义

请求：

```text
GET /source/api/v1/search?def=InitParamService&projects=openharmony&type=c&maxresults=5&maxhitsperfile=2
```

响应 HTTP 200，`resultCount=2`，命中：

```text
/openharmony/base/startup/init/services/param/liteos/param_service.c:62
/openharmony/base/startup/init/services/param/linux/param_service.c:412
```

这证明 `def`（单数）可以用于定位 C 函数定义，并且 `start` 分页参数有效。

### 4.2 函数引用/调用位置

请求 `symbol=OnIncomingConnect&projects=openharmony` 返回 HTTP 200，共 4 个文档，包含 `param_service.c` 中的函数定义及测试调用位置。未加 `type` 时，`symbol=OnRemoteRequest` 返回大量 C++ 调用位置；加 `type=cxx` 后返回 C++ 文件结果。

### 4.3 宏定义到服务路径

对 `full="/dev/unix/socket/paramservice"` 的搜索返回 HTTP 200、`resultCount=94`。结果包含目标头文件，但也包含 SELinux 文件、构建输出和日志等噪声。这说明 `full` 是分词检索，不能直接把结果数当作精确命中。

通过 raw 源码读取进一步确认：

- `base/startup/init/services/param/include/param_utils.h` 定义 `CLIENT_PIPE_NAME` 和 `PIPE_NAME`，其中包含 `/dev/unix/socket/paramservice`。
- `base/startup/init/services/param/linux/param_service.c` 的 `InitParamService` 将 `PIPE_NAME` 作为服务路径，并把 `OnIncomingConnect` 注册为 `incomingConnect` 回调。
- `param_service.c` raw 响应 HTTP 200、`Content-Type: text/plain`、约 19.9 KB。

因此，宏路径定位需要“搜索候选 → 读取源码 → 沿宏定义/引用核验”，不能只依赖一次 `full` 搜索。

### 4.4 文件类型筛选

网页搜索表单显示的 C++ 类型值是 `cxx`，不是 `cpp`。实测：

- `type=c` + `def=InitParamService`：命中 2 个 C 文件；
- `type=cpp`：HTTP 200 但结果为 0；
- `type=cxx` + `symbol=OnRemoteRequest`：命中 C++ 文件。

适配器必须使用 OpenGrok 的类型值（如 `c`、`cxx`），并允许部署差异通过能力探测或配置覆盖。

## 5. OpenAPI 与实际部署的差异

提供的 `openapi.yaml` 是 OpenAPI 3.0.3，服务器相对路径为 `/api/v1`，使用 Bearer token 描述受保护端点。文档说明搜索、文件、历史和 suggester 是否需要登录取决于部署的授权框架。

本实例的行为是：搜索、健康检查、索引时间和 suggester 配置公开；文件、目录、项目和仓库元数据返回 401；网页 `/raw`、`/xref` 路由却公开可读。因此不能把 OpenAPI 的“可调用”理解为“本实例必然免认证”，也不能只实现 `/file/content` 就认为源码读取完整。

另外，REST 搜索参数使用 `def`，而 suggester 请求体参数使用 `defs`/`refs`。适配器不能把两个接口的字段名混用。`suggest` 的 `caret` 必须不大于对应输入文本长度；输入长度错误时实例返回 HTTP 500，而不是友好的 4xx。

## 6. 对 OpenAnt 工具的建议

### 6.1 第一优先级（MVP 必须有）

1. `opengrok_probe`：调用 `system/ping`、`system/indextime`、`suggest/config`，记录版本线索、索引时间和端点能力。
2. `opengrok_search`：只读 GET，支持 `def`、`symbol`、`full`、`path`、`type`、项目过滤、分页和结果上限；默认显式传项目名。
3. `opengrok_read_source`：读取顺序为 REST `/file/content`（有 token 时）→ 网页 `/raw/<path>`（本实例可用）→ 可选 `/xref/<path>`。返回内容、来源端点、HTTP 状态和索引/修改时间，不把 HTML 当源码交给模型。
4. `opengrok_evidence`：保留原始命中路径/行号/片段，同时提供清洗后的文本。搜索片段中的 `<b>`、`&lt;`、`&amp;` 和 `\r` 必须安全解码，不能丢掉证据来源。

### 6.2 第二优先级（提高定位质量）

- 用 `def`/`symbol` 精确查询作为第一步，`path` 和 `full` 作为候选扩展；不要把 quoted `full` 当作精确路径匹配。
- 对 `out/`、日志、生成目录、测试目录、SELinux 策略等结果做“排序降权”而不是无条件删除，以免漏掉初始化或 fuzz 入口。
- 查询候选使用 `type=c`、`type=cxx` 等真实类型值；未知类型先探测或不传类型。
- 对 `start`/`maxresults`/`maxhitsperfile` 设置硬上限，避免把大量噪声送给模型。
- 将 `/openharmony/` 项目前缀与仓库内相对路径分开保存，避免后续本地 clone 路径拼接错误。

### 6.3 暂不应接入

OpenAPI 中的配置修改、项目增删、索引标记、suggester 重建、消息和所有 POST/PUT/DELETE 操作不属于源码定位必需能力，不应开放给定位 Agent。若今后确有运维需求，应单独做管理员接口和权限隔离。

## 7. 认证、缓存和可靠性要求

- Bearer token 通过服务端环境变量或项目私有配置注入，禁止写入日志、提示词、测试记录和浏览器端。
- 所有上游请求限制为 HTTPS、固定允许的主机/路径和只读 GET；禁止跟随到非允许主机的重定向。
- 对源码响应设置字节上限、超时和缓存键（实例、项目、路径、索引时间）；缓存不能掩盖索引时间变化。
- 将 401、403、404、406、429、5xx 分成“需要凭据、路径不存在、内容类型不适合、限流、上游故障”，交给 Agent 可理解的错误，而不是把 HTML 错误页当源码。
- `/raw` 是本次实例验证出的兼容扩展，不在官方 OpenAPI 中，必须通过启动探测标记为能力，不可假设所有 OpenGrok 都支持。

## 8. 结论

本实例可以稳定调用 OpenGrok 的健康检查、索引时间和搜索 REST API；源码/目录/项目 REST API 在无 token 时被保护，但网页 `/raw` 和 `/xref` 可用。因此 OpenAnt 可以实现源码定位 MVP，但应采用“REST 搜索 + `/raw` 纯文本回退 + 可选 Bearer 的 `/file/content`”的后端适配，而不是只依赖 `/file/content` 或让浏览器直接跨域请求。

本轮没有修改 OpenAnt 业务代码；下一步可在确认后实现上述只读适配器和自动化回归测试。
