# OH-SL-00B：源码定位器配置模型测试记录

日期：2026-08-28
阶段：源码定位器 SL-00B（配置模型与探测结果契约）
目标：在现有 `config/openant/config.json` 中提供可选的 `source_locator` 配置节，并把 OpenGrok 连接参数、认证策略、仓库映射约束和无凭据探测结果纳入统一的类型模型。

## 1. 原项目逻辑与修改后逻辑

原项目的配置模型只关注 LLM。OpenGrok 客户端虽然已经可以接收 URL、项目名、API 前缀、超时和 token，但调用方需要手工拼接这些参数；配置文件中没有定位器的结构化校验，Python 配置序列化也不会保留未知的定位器字段。

修改后，主配置文件可以选择性加入：

```json
{
  "source_locator": {
    "enabled": true,
    "target_revision": "OpenHarmony-6.1-LTS",
    "opengrok": {
      "base_url": "https://example.invalid/source",
      "project": "openharmony",
      "api_prefix": "/api/v1",
      "timeout_seconds": 15,
      "auth": {"mode": "bearer_env", "token_env": "OPENANT_OPENGROK_TOKEN"}
    },
    "manifest": {"source": "local", "path": "config/openharmony/ohos.xml"},
    "gitcode": {
      "allowed_hosts": ["gitcode.com"],
      "allowed_orgs": ["openharmony"],
      "destination_root": "source_code_base"
    }
  }
}
```

新增的 `core/source_locator/config.py` 提供以下行为：

- `source_locator` 不存在时返回 `None`，旧的直接扫描流程保持不变；
- OpenGrok 地址必须是无凭据的 HTTPS URL，项目、API 前缀、超时、重试次数、源码大小和搜索上限均有边界；
- 认证策略只有 `none` 和 `bearer_env`。JSON 只保存环境变量名，实际 token 仅在构造 HTTP 客户端时从环境读取；
- revision、Manifest 路径、GitCode 主机/组织白名单和目标目录进行路径/字符校验，不接受穿越或任意远端凭据；
- `last_probe` 可保存 `ProbeResult` 的版本、索引时间、端点状态和警告，模型不会保存请求头或 token；
- `OpenGrokConfig.build_client()` 将已校验配置转换为现有只读客户端，尚未执行网络请求；
- Python 的 `ConfigFile` 现在保留并序列化这个类型化的可选节，Go 侧已有未知字段保留机制，因此配置往返不会丢失该节。

本阶段仍不执行 Manifest 下载、仓库映射、Git clone 或定位会话；配置模型只是这些后续动作的安全输入边界。

## 2. 文件变更

- `libs/vulnfounder-core/core/source_locator/config.py`
- `libs/vulnfounder-core/core/source_locator/__init__.py`
- `libs/vulnfounder-core/utilities/llm/config.py`
- `libs/vulnfounder-core/tests/source_locator/test_config.py`

没有修改 `config/openant/config.json`，因此当前项目默认不会自动启用源码定位流程，也不会触发新的网络访问。

## 3. 独立测试

### 3.1 配置与 OpenGrok 回归

执行：

```text
cd libs/vulnfounder-core
../../.venv/bin/python -m pytest -q \
  tests/source_locator/test_config.py \
  tests/source_locator/test_opengrok_live_fixture_contract.py \
  tests/test_opengrok_client.py \
  tests/test_opengrok_protocol_models.py \
  tests/test_llm_config_schema.py
```

结果：`56 passed in 0.06s`。

覆盖内容包括：

- 旧配置缺少 `source_locator` 时仍能解析；
- 新配置解析、序列化、再次解析的一致性；
- token 只从环境变量读取，序列化结果不包含 token；
- Bearer 头只在 HTTP 客户端内部使用；
- `ProbeResult` 挂载、序列化和恢复；
- 缺失地址、HTTP 地址、危险 API 前缀、非法环境变量名和危险 revision 的 fail-closed 行为；
- 禁用配置和 `required=True` 的缺失配置错误；
- SL-00A 真实响应回放和已有 OpenGrok 客户端测试不回归。

### 3.2 项目配置兼容性

使用当前项目真实 `config/openant/config.json` 进行解析，确认其没有 `source_locator` 时得到 `source_locator is None`，LLM 配置正常解析。

结果：`project config compatibility: source_locator absent and parsed`。

### 3.3 静态检查

```text
.venv/bin/ruff check \
  libs/vulnfounder-core/core/source_locator/config.py \
  libs/vulnfounder-core/core/source_locator/__init__.py \
  libs/vulnfounder-core/utilities/llm/config.py \
  libs/vulnfounder-core/tests/source_locator/test_config.py
```

结果：`All checks passed!`；`git diff --check` 通过；Python `compileall` 通过。

## 4. 结论与边界

SL-00B 已证明定位器配置可以安全地嵌入现有配置体系，并且旧配置行为不变。认证信息不会进入配置序列化、探测结果、日志或提示词。

本阶段没有验证真实网络探测，因为能力回放已在 SL-00A 固定；也没有把 `source_locator` 加入项目默认配置，所以用户仍需显式配置并由后续命令选择启用。下一阶段应在本配置模型上实现目标标准化和固定的初始查询计划。
