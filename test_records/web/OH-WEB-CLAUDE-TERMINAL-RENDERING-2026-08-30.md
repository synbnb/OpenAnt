# OH-WEB-CLAUDE-TERMINAL-RENDERING-2026-08-30

## 目标

修复动态测试中 Claude Code PTY 输出在 Web 对话窗口内出现控制字符、行重绘和碎片化显示的问题。

## 修改内容

- 后端新增跨读取分片的 PTY 输出解码器：过滤 ANSI/OSC/清屏/光标/颜色控制序列，处理被拆开的控制序列和 UTF-8 字符，并将回车重绘转换为可读换行。
- 前端将连续 Claude 输出合并为单个终端文本块，使用 `pre` 保留空格、换行和制表符，限制单块缓存大小避免长会话拖慢页面。
- 前端对历史和实时输出统一过滤 Ink 专用界面行（长边框、`❯` 输入提示、权限状态栏、更新提示和孤立的 `Claude` 标题），避免把终端装饰误显示为模型回答；保留正文、代码、命令结果和用户输入。
- 动态测试窗口高度、行距、制表位和长路径换行策略同步调整；对历史会话增加前端防御性清理。

## 自动化验证

执行目录：`apps/vulnfounder-cli`

```text
go test ./...
ok   github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server
其余包均通过（无失败测试）
```

另外执行 `go test -race ./internal/server` 和 `go vet ./...`，均通过。

新增覆盖：

1. ANSI CSI 序列跨 PTY 分片拼接后不会泄漏到文本。
2. OSC、字符集切换、清屏和 C0 控制字符不会出现在浏览器内容中。
3. CRLF 被规范化为一个换行。
4. UTF-8 字符跨读取边界时不会产生替换字符或丢字。
5. 原有 PTY 会话回放、输入回车提交和结果收集测试继续通过。
6. 通过伪 Claude PTY 进程输出分片 ANSI/UTF-8 控制内容，端到端验证会话事件中不再泄漏控制噪声。

同时执行：

```text
sed -n '/<script>/,/<\\/script>/p' apps/vulnfounder-cli/ui/scan.html | sed '1d;$d' | node --check
git diff --check -- apps/vulnfounder-cli/internal/server/claude_session.go \
  apps/vulnfounder-cli/internal/server/claude_web_test.go apps/vulnfounder-cli/ui/scan.html
```

两项均无输出，表示页面脚本语法和补丁格式检查通过。

另用 Node 对用户截图中的实际 PTY 片段（`⏺` 正文、长边框、`❯`、`Claude`、权限状态栏和 spinner）执行过滤冒烟测试，结果为 `Claude terminal chrome filter smoke test passed`。

检查现场进程时发现 `127.0.0.1:18080` 由较早启动的 PID 9275 提供，当前 Claude 子进程 PID 98626 仍在该会话中运行；旧进程响应中没有本次新增的 `claude-output-stream` 标记，而新二进制已包含该标记。因此验证页面改动前应先在 Web 中停止当前 Claude 会话，确认 PID 98626 消失，再重启 PID 9275 对应的 Web 服务并强制刷新浏览器。

已执行 `go build -o bin/openant .`，新的 Web 二进制已写入项目现有 `apps/vulnfounder-cli/bin/openant`。由于 Web 页面通过 Go `embed` 内嵌到启动时的进程，已有旧进程必须在当前 Claude 会话结束后重启，浏览器强制刷新后才会加载本次页面改动。

## 预期 Web 效果

重新启动 Web 后，在扫描详情的“动态测试”阶段打开 Claude Code 对话：终端输出应以连续的可读文本显示，不再出现 `^[`、`[2K`、颜色码、光标定位残片或每个分片重复一行标签。长路径会在窗口内换行，窗口高度可随桌面视口扩展。

## 限制

该实现将交互式终端重绘转换为追加式审计记录，不模拟完整终端光标位置；因此 Claude 的进度重绘可能保留少量历史版本行，但会过滤常见 Ink 装饰行，不再显示不可读的 ANSI 控制噪声。 
