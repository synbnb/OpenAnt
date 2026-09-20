# OH-SL-02 OpenGrok 只读客户端实现与实测记录

日期：2026-08-28  
阶段：OpenHarmony 源码定位前置环节 / SL-02 只读 OpenGrok 客户端  
范围：协议模型、HTTP 探测、搜索、源码读取回退；不包含 Agent、Web、Git clone。

## 1. 原逻辑与本阶段逻辑

### 修改前

VulnFounder 中没有 OpenGrok 客户端实现。源码定位方案只有文档设计，现有扫描流程仍要求用户提供本地源码目录。

### 修改后

新增 `core/source_locator` 包，提供：

- `OpenGrokClient`：仅暴露只读 GET 操作；
- `probe()`：探测根页面、ping、索引时间、suggester、搜索，以及用户指定路径的 file/raw/xref 能力；
- `search()`：将 Python 参数映射为 OpenGrok REST 查询，支持 `def`、`symbol`、`full`、`path`、类型筛选、项目、分页和排序；
- `read_source()`：优先读取 `/api/v1/file/content`，失败后读取 `/raw/<path>`；
- 有限重试：最多 3 次，总体只重试网络错误和 429/5xx；
- 路径校验：拒绝 URL、查询/片段、空字节、反斜杠和 `..`；
- 证据保留：搜索命中同时保存原始 HTML 片段和清洗后的文本；
- 安全错误：不把上游 HTML 错误正文和 Bearer token带入异常文本或尝试记录；
- 内容类型保护：不把 `text/html` 或 XHTML 页面当作源码。

本阶段没有把客户端接入 Web 或 CLI，因此不会改变现有扫描行为。

## 2. 修改文件

- `libs/vulnfounder-core/core/source_locator/__init__.py`
- `libs/vulnfounder-core/core/source_locator/opengrok_client.py`
- `libs/vulnfounder-core/tests/test_opengrok_protocol_models.py`
- `libs/vulnfounder-core/tests/test_opengrok_client.py`

## 3. 自动化测试

### 定向测试

命令：

```text
.venv/bin/python -m pytest -q \
  tests/test_opengrok_protocol_models.py \
  tests/test_opengrok_client.py
```

结果：`28 passed`。

覆盖内容：

- OpenGrok base URL、API 前缀和源码路径安全校验；
- `<b>`、HTML 实体、CRLF 清洗及原始片段保留；
- 搜索响应字段和分页结构解析；
- API 查询参数、项目默认值和 `c` 类型传递；
- Bearer 头不出现在日志/错误中；
- `/file/content` 401 后回退 `/raw`；
- 大文件截断标记；
- 503 重试一次；
- 探测公开端点与需要认证的端点；
- 缺少路径时的能力探测警告；
- 网络失败、非 2xx 和 HTML 响应的错误边界。

### 静态检查

命令：

```text
.venv/bin/ruff check \
  libs/vulnfounder-core/core/source_locator \
  libs/vulnfounder-core/tests/test_opengrok*
python -m compileall -q core/source_locator
```

结果：Ruff 通过，Python 编译通过。

### 全量测试说明

使用项目 `.venv` 执行全量 pytest 时，首先遇到仓库既有的 Go 一致性测试失败：测试内部调用 `go`，但当前执行环境的 PATH 没有 `go` 命令。之后全量集合还包含设备/外部依赖测试，曾在约 96% 处长时间等待；为避免无限等待已中止。该失败发生在 OpenGrok 客户端之外；本片新增定向测试全部通过。

## 4. 真实 OpenGrok 回归

实例：

```text
https://u375886-9ad1-ba9448df.westc.seetacloud.com:8443/source
```

脚本使用真实客户端执行：

```text
client.probe(
  probe_path="/openharmony/base/startup/init/services/param/linux/param_service.c"
)
client.search(definition="InitParamService", file_type="c")
client.read_source("/openharmony/base/startup/init/services/param/linux/param_service.c")
```

结果：

- `reachable=True`；版本识别为 `OpenGrok 1.14.11 (...)`；
- `ping`、`indextime`、`suggest_config`、`search`、`raw`、`xref` 返回可用；
- `file_content` 返回 401，并正确标记为需要认证；
- `def=InitParamService&type=c` 返回两个真实定义：Linux 与 LiteOS 的 `param_service.c`；
- 源码读取尝试状态为 `[401, 200]`，最终来源为 `raw`；
- 完整源码大小约 19,898 字节，未截断；
- 源码中确认包含 `OnIncomingConnect`、`InitParamService` 和 `PIPE_NAME`。

真实回归期间发现并修复了页面 generator 内容前多出的模板字符 `{`，版本结果现在规范为 `OpenGrok 1.14.11 (...)`。

## 5. 本阶段结论

只读客户端已经能兼容当前实例的实际权限模型：REST 搜索可用，REST 文件接口需要 token 时自动使用公开 raw 文本回退。它没有引入任何写操作，也没有改变原有扫描流程。

下一阶段才接入配置/CLI 或 Web；届时仍需保持后端代理、主机白名单、请求字节上限和 token 脱敏。
