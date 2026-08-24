# Claude Code 面板阶段归属测试记录

日期：2026-08-24  
范围：扫描详情页阶段菜单与 Claude Code 动态验证面板

## 问题

Claude Code 对话区块原本是阶段详情区下方的独立区块。只要任务启用了 Claude Code 动态测试，它就会在解析、上下文、分析、验证等所有阶段下方显示，用户容易误以为这些阶段都在使用 Claude 交互。

## 修改

文件：`apps/openant-cli/ui/scan.html`

- Claude 面板增加 `data-stage-panel="dynamic-test"` 标识。
- 新增 `syncClaudePanelVisibility()`：只有 `selectedStage === "dynamic-test"` 且动态测试已启用时显示面板。
- 阶段菜单切换时立即同步面板可见性。
- Claude 状态刷新时继续使用同一规则；动态会话运行时仍会自动切换到动态测试阶段（用户手动选择其他阶段后不强制跳转）。
- 对话、SSE、任务目录和文件查看逻辑保持不变。

## 验证

### 前端语法

```text
node --check <(awk 'BEGIN{p=0} /<script>/{p=1;next} /<\/script>/{p=0} p' apps/openant-cli/ui/scan.html)
```

结果：通过。

### Go Web 测试与构建

```text
GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go test ./internal/server

GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go build -o bin/openant .
```

结果：测试通过，构建成功。

### HTTP 模板冒烟

用最新二进制重启 `http://127.0.0.1:18080/`，访问现有历史扫描详情页并检查返回 HTML：

- 动态测试菜单存在
- Claude 区块包含 `data-stage-panel="dynamic-test"`
- 返回页面包含 `syncClaudePanelVisibility()`
- HTTP 状态正常

## 预期使用方式

1. 用户点击“源码解析、应用上下文、漏洞分析”等菜单时，Claude 面板隐藏。
2. 用户点击“动态测试”菜单时，Claude 面板显示在动态测试阶段详情下方。
3. 动态会话运行期间，如果用户没有手动选择其他阶段，页面自动切换到动态测试；如果用户已手动查看其他阶段，不会被强制打断。
