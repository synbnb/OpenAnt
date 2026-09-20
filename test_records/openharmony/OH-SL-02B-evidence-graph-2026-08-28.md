# OH-SL-02B：源码证据存储与证据图测试记录

日期：2026-08-28
阶段：源码定位器 SL-02B（EvidenceStore、EvidenceGraph 与确定性证据评分）
性质：离线测试，不调用大模型，不修改 OpenGrok 远端状态

## 1. 原项目逻辑与修改后逻辑

原项目在源码定位阶段已经能够保存 OpenGrok 搜索结果、路径和源码文档，但还没有统一的“可引用证据”对象：搜索命中、源码读取片段和后续关系没有共同的 ID，图边也没有强制反查来源。因此，仅凭一段自然语言描述无法判断它是否真的来自仓库源码。

本阶段新增一条确定性的证据链：

```text
OpenGrok SearchHit / SourceDocument
  → 清洗并限制源码片段
  → 规范化仓库路径和行号
  → 记录原始片段、清洗片段、来源工具/端点、query_id 和 SHA-256
  → 按 kind + path + line range + symbol 稳定去重
  → 生成证据 ID（E-...）
  → 图边只能引用已登记的证据 ID
  → 通过 edge_id 反查完整证据
  → 对唯一证据做可解释排序评分
```

评分只用于安排后续核查，不直接等同于漏洞结论或服务归属结论。`socket_bind_listen` 只有创建者证据时会标记为 `creator_only`，不会被判定为已确认服务端；必须同时具备服务端消费/分派证据，并有 socket 身份或服务映射证据，结构谓词才会变为 `confirmed_server=true`。

## 2. 实现文件

- `libs/vulnfounder-core/core/source_locator/evidence_store.py`
  - `Evidence`：保存路径、行号、原始/清洗片段、来源、哈希和查询 ID；
  - `EvidenceStore`：稳定去重、序列化、搜索命中/源码文档转换和反向查询；
  - `EvidenceEdge` / `EvidenceGraph`：强制图边引用已存在证据，支持边合并和反查。
- `libs/vulnfounder-core/core/source_locator/evidence_scoring.py`
  - 证据类型权重、分数明细和服务端强制谓词；
  - 重复 evidence ID 在聚合评分中只计算一次。
- `libs/vulnfounder-core/core/source_locator/__init__.py`
  - 导出上述公共类型和函数。
- `libs/vulnfounder-core/tests/source_locator/test_evidence_store.py`
  - 专项测试和 `paramservice` 真实 OpenGrok 片段离线回放。

## 3. OpenHarmony 真实夹具回放

测试读取此前只读获取的夹具：

```text
tests/source_locator/fixtures/opengrok/live_1_14_11/raw_param_service_excerpt.c
```

该夹具来自 OpenGrok raw 响应的脱敏片段，包含 `OnIncomingConnect`、`InitParamService`、`PIPE_NAME` 的使用以及 `info.incomingConnect = OnIncomingConnect` 注册关系。测试在不访问网络的情况下，将第 9 行的 socket 标识使用和第 13 行的回调注册转换为证据，再构造两条可反查图边，验证路径和行号没有丢失。

另外使用 OpenGrok 搜索响应模型回放了宏命中场景，验证 `<b>...</b>` 标记、HTML 实体和换行能够同时保留原始片段与清洗片段。

## 4. 独立测试结果

### 4.1 专项测试

```text
cd libs/vulnfounder-core
../../.venv/bin/pytest -q tests/source_locator/test_evidence_store.py
17 passed in 0.03s
```

覆盖内容：

- 相同 `kind/path/line/symbol` 去重，保留首次查询的审计信息并记录重复次数；
- 控制字符替换、片段长度上限和 CRLF 规范化；
- 不安全路径、缺少 OpenGrok 行号、源码行范围越界拒绝；
- SearchHit 和 SearchResponse 的来源端点、工具名、query_id 追溯；
- SourceDocument 对完整源码计算哈希、只保存请求的行范围；
- 悬空 evidence ID 和空证据图边拒绝；
- 同端点图边合并，不产生重复边；
- JSON 序列化/反序列化及损坏版本拒绝；
- `paramservice` 夹具注册图离线重建；
- 重复证据不增加分数，creator-only 不确认服务端，加入消费和身份证据后才满足结构谓词。

### 4.2 相关阶段回归

```text
../../.venv/bin/pytest -q tests/source_locator
72 passed in 0.07s
```

```text
../../.venv/bin/ruff check \
  core/source_locator \
  tests/source_locator/test_evidence_store.py
All checks passed!
```

Python `compileall` 和 `git diff --check` 均通过。

### 4.3 全仓库回归边界

曾执行 `.venv/bin/pytest -q --maxfail=1`，在本阶段代码运行前 6 个测试通过后，首个失败是既有 Go 解析器一致性测试：测试临时目录需要调用 `go test`，当前环境没有 `go` 可执行文件（`FileNotFoundError: [Errno 2] No such file or directory: 'go'`）。该失败与本阶段 Python 证据图代码无关，因此本记录以 source_locator 专项及相关阶段回归作为有效结果；未声称全仓库已全部通过。

## 5. 安全和设计边界

- 证据片段最多保存 4096 个字符，ASCII 控制字符替换为空格，避免终端转义或 NUL 进入报告/提示词；
- 源码路径复用 OpenGrok 的严格路径规范化，拒绝 URL、反斜杠和穿越片段；
- 内容哈希来自完整 `SourceDocument`，片段哈希只在没有完整源码时作为回退，不能替代 revision；
- 图边没有证据 ID 时直接失败，模型自然语言不能单独创建源码关系；
- 评分和结构谓词分开保存，分数不会因为重复搜索或重复引用而膨胀；
- 本阶段不做 Manifest 仓库映射、不执行 git clone、不调用 LLM，也不改变现有扫描 reachable 范围。

## 6. 结论

SL-02B 已完成：OpenHarmony 源码命中和源码片段现在可以形成稳定、可审计、可序列化的证据对象；每条关系都能通过边反查到文件和行号；重复证据不会人为提高可信度；仅有 socket 创建者证据不会误报为已确认服务端。下一阶段可以在此基础上实现服务端归因和 Manifest/GitCode 仓库映射，但必须继续沿用“关系先有源码证据、模型文字只作解释”的约束。
