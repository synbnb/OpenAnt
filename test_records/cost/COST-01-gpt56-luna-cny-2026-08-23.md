# COST-01：gpt-5.6-luna 人民币费用链路

日期：2026-08-23  
范围：模型注册、LLM 计费、阶段报告、CLI/Web 展示  
状态：已完成本阶段，待用户审阅

## 1. 原逻辑与本阶段修改

原逻辑把所有费率都当作美元，`TokenTracker` 只维护 `total_cost_usd` 和
`cost_usd`。用户配置的 `autodl-openai / gpt-5.6-luna` 不在
`config/models.json`，因此 `lookup_pricing` 得不到费率，跟踪器会发出未知模型警告并把费用记为 0。

本阶段采用不换算汇率的并行字段方案：

1. `config/models.json` 新增 `gpt-5.6-luna`：输入 `0.812 CNY/M`，输出
   `4.872 CNY/M`，并声明 `currency: CNY`。
2. 模型注册器新增币种和带币种的费率查询；旧模型未声明币种时仍默认 USD。
3. `lookup_pricing` 对非美元模型附加 `currency`，TokenTracker 新增
   `cost_amount`、`cost_currency`、`cost_cny`、`costs_by_currency`，同时保留
   `cost_usd`/`total_cost_usd` 兼容历史产物。
4. `StepReport`、`scan.report.json`、checkpoint 汇总、CLI 输出、HTML 报告数据和
   Web pipeline JSON/页面都按声明币种显示，不把人民币数值伪装成美元，也不做隐式汇率换算。

## 2. 计算核对

使用实际运行配置文件中的默认阶段绑定（未打印密钥）：

```text
provider config name: autodl-openai
model: gpt-5.6-luna
lookup_pricing: input=0.812, output=4.872, currency=CNY
```

用输入 1,000,000 token、输出 1,000,000 token 的离线计费样例核对：

```text
费用 = 1 × 0.812 + 1 × 4.872 = ¥5.684
cost_usd = 0
cost_amount = 5.684
cost_currency = CNY
```

阶段报告实际写入：

```json
{
  "cost_amount": 5.684,
  "cost_currency": "CNY",
  "cost_cny": 5.684,
  "cost_usd": 0.0,
  "costs_by_currency": {"CNY": 5.684}
}
```

## 3. 自动化测试记录

### Python（通过）

命令：

```bash
PYTHONPATH=libs/openant-core \
  /Users/shiyu/miniconda3/bin/pytest -q \
  libs/openant-core/tests/test_model_registry.py \
  libs/openant-core/tests/test_token_tracker.py \
  libs/openant-core/tests/test_step_report_currency.py \
  libs/openant-core/tests/test_llm_helpers_unit.py::TestLookupPricing
```

结果：`23 passed`。

另一次包含旧模型集中测试和未知模型费用回归的运行结果：`29 passed, 1 failed`；失败是
环境缺少 `google-genai`，发生在既有 Google adapter 导入测试，不涉及本次费用代码。

### Python 全量收集（环境阻塞，非代码断言失败）

全量测试无法完成收集，当前 Miniconda 环境缺少仓库声明的多个 Tree-sitter 包
（包括 `tree-sitter-c`、PHP、Ruby、Rust、Zig 等）和 `google-genai`，共导致相关测试
在收集阶段导入失败。没有将这些环境错误冒充为本阶段回归失败。

### Go（通过）

命令：

```bash
GOCACHE=/private/tmp/openant-go-build \
GOMODCACHE=/private/tmp/openant-go-mod \
  ../../.devtools/go1.25.7/go/bin/go test ./...
```

结果：所有 Go package 通过。新增覆盖包括：

- Web pipeline 对 `cost_currency=CNY`、`costs_by_currency` 的投影；
- CLI 输出费用按 `¥` 展示；
- HTML 报告总费用按声明币种展示。

### Web 现场检查

已用新二进制重建并启动本地服务。第一次启动时发现旧的 OpenAnt Web 进程（PID `53344`）
仍占用 `127.0.0.1:18080`，已确认后停止；随后也停止了本次临时回退实例并重新绑定：

```text
http://127.0.0.1:18080
```

历史扫描 `9b7f539401760206` 的 `/pipeline` 接口可正常返回；旧报告没有人民币费用，因而显示
0 是预期的向后兼容行为。新扫描生成的阶段报告含 CNY 字段后，前端会显示 `¥`。

扫描详情页实际包含 `formatPipelineCost` 和 `costs_by_currency` 逻辑；用 Node 对内嵌
JavaScript 执行语法检查通过。

## 4. 当前限制与下一阶段建议

- 旧的动态测试专用字段仍命名为 `generation_cost_usd`，本阶段没有扩展动态测试；动态测试
  按用户决定暂缓。
- Python 全量测试需要先按项目依赖安装完整 Tree-sitter 语言包和 `google-genai`，再进行
  环境恢复后的全量回归。
- 如用户审阅通过，下一小阶段可以对真实扫描产物（不调用额外 API 的本地 fixture 或用户
  已完成的扫描）逐个核对 `scan.report.json`、阶段 report、pipeline JSON 和 Web 展示。
