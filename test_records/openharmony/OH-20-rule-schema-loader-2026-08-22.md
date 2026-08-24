# OH-20：OpenHarmony 安全规则 schema 与 loader 测试记录

日期：2026-08-22  
阶段：阶段 2（规则、Finding 融合和原生验收）的 OH-20  
状态：通过

## 1. 阶段边界

本阶段只建立规则目录的可靠输入边界，不接入漏洞检测，也不改变现有 Finding
结论。`security-skill-library` 仍作为规则意图参考，未直接调用其中的 `scan.py`
并把脚本输出当作高置信结论。

旧逻辑没有统一的规则 schema/loader，规则文件的版本、适用平台和来源无法被
OpenAnt 确定性记录。新逻辑新增：

- `core/rules/schema.py`：严格校验规则 ID、版本、标题、平台、严重级别、
  detector 和 JSON-like config；
- `core/rules/loader.py`：安全读取 YAML、默认资源发现、跨文件合并和诊断；
- `core/rules/defaults/openharmony.yaml`：一个只描述 `OH-IPC-001` 的初始默认
  规则元数据，当前尚未接入 detector 执行；
- `pyproject.toml` 的精确 `force-include`，保证默认 YAML 进入 wheel。

## 2. schema 契约

顶层格式：

```yaml
schema_version: 1
rules:
  - id: OH-IPC-001
    version: 1.0.0
    title: ...
    description: ...
    platforms: [openharmony]
    severity: high
    detector: parcel_read_return_value
    config: {}
    references: []
    tags: []
```

当前限制：

- schema 版本必须是 `1`；
- ID 使用大写分段格式，例如 `OH-IPC-001`；
- 版本使用 `MAJOR.MINOR.PATCH`；
- severity 只能是 `info/low/medium/high/critical`；
- 平台和 detector 必须是小写 slug；
- 单文件默认不超过 1 MiB、256 条规则、128 个发现文件；
- config 只接受有限深度和大小的 JSON-like 值，不接受 Python/YAML 可执行对象；
- YAML anchor/alias 主动拒绝，避免别名扩展造成内存放大。

## 3. TDD 记录

### RED

先运行新增测试：

```text
./.venv/bin/python -m pytest -q \
  libs/openant-core/tests/rules/test_rule_loader.py
```

结果：收集阶段失败：

```text
ModuleNotFoundError: No module named 'core.rules'
```

实现 schema/loader 后，测试夹具最初有 2 项失败。复核发现夹具复用了同一
list/dict，`yaml.safe_dump` 自动生成了 anchor/alias；loader 正确拒绝 alias，
因此修正夹具为深拷贝后继续测试。

### GREEN

规则专项最终结果：

```text
./.venv/bin/python -m pytest -q \
  libs/openant-core/tests/rules/test_rule_loader.py

11 passed in 0.04s
```

覆盖内容：

1. 合法规则解析和原始文件 SHA-256 稳定性；
2. 单条坏规则不阻塞合法兄弟规则；
3. 未知字段、重复 ID 和跨文件重复 ID；
4. malformed YAML；
5. YAML anchor/alias；
6. 超大文件、规则数量过多和配置嵌套过深；
7. 默认包资源发现；
8. wheel `force-include` 声明。

相关回归：

```text
./.venv/bin/python -m pytest -q \
  libs/openant-core/tests/rules \
  libs/openant-core/tests/openharmony \
  libs/openant-core/tests/test_installed_layout.py -m 'not slow'

60 passed, 2 skipped, 2 deselected in 0.58s
```

静态质量检查：

```text
.venv/bin/ruff check libs/openant-core/core/rules \
  libs/openant-core/tests/rules

All checks passed!
```

## 4. fail-safe 行为

`RuleLoader.load_file()` 对以下情况返回空规则加 `RuleIssue`，不向扫描主流程抛出
未处理异常：

- 文件过大：`file_too_large`；
- 路径 I/O 或 UTF-8 错误；
- YAML 语法错误：`yaml_parse_error`；
- YAML anchor/alias：`yaml_alias_not_allowed`；
- 顶层字段/版本/规则列表错误；
- 单条规则字段、严重级别、config 或版本错误。

合法规则会继续保留；重复 ID 只保留第一次，并记录 `duplicate_rule_id`。
每个文件保留原始字节数和 `source_sha256`，合并目录另外生成确定性的
`catalog_sha256`。

## 5. 安装验证说明

已通过静态检查确认 `pyproject.toml` 包含：

```text
"core/rules/defaults/openharmony.yaml" =
  "core/rules/defaults/openharmony.yaml"
```

虚拟环境当前没有 `build` 模块，因此两个真实 wheel 构建测试按既有测试约定跳过：

```text
SKIPPED ... wheel build unavailable here: No module named build
```

源码 checkout 下的 `importlib.resources` 默认资源发现已由专项测试验证。安装后
的最终 wheel 包含性需要在安装 `build` 依赖或 CI 环境中补跑。

## 6. 下一步

OH-20 只提供规则输入边界，尚未执行规则。下一阶段是 OH-21：建立有限数据流和
guard dominance，令规则能够沿 Parcel read、source/sink 和权限检查路径给出可追踪
证据。

