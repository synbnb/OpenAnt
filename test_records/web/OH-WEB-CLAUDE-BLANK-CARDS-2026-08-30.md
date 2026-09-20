# OH-WEB-CLAUDE-BLANK-CARDS-2026-08-30

## 问题

Claude Code 交互期间，Web 对话区会不断出现只有“Claude”标题、没有正文的空白消息块。

## 根因

Claude Code 使用 Ink 绘制终端界面。PTY 会持续输出边框、输入提示、spinner、状态栏和清屏重绘帧。服务端已经去除了 ANSI 控制序列，但这些重绘帧在语义上仍可能是非空字符串。前端旧逻辑先创建 Claude 消息块，再过滤终端装饰；当过滤结果为空时就留下了空白消息块。

## 修复

修改 `apps/vulnfounder-cli/ui/scan.html`：

- 先把当前 PTY 输出合并并经过终端装饰过滤。
- 只有过滤后存在可见正文时才创建或更新 Claude 消息块。
- 纯边框、spinner、输入提示和状态栏不会再生成空白卡片。
- 纯重绘帧不会提前移除“等待 Claude Code 连接”提示。
- 已存在的正文消息不会因为后续纯重绘帧被清空。

## 验证

执行目录：`apps/vulnfounder-cli`

```text
go test ./...
ok   github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server
其余 Go 包全部通过
```

```text
sed -n '/<script>/,/<\\/script>/p' apps/vulnfounder-cli/ui/scan.html | sed '1d;$d' | node --check
无输出，页面脚本语法通过
```

使用实际终端片段进行 Node 冒烟检查：

```text
纯 Ink 重绘帧过滤结果为空，不生成消息卡片
真实中文回复“你好，已读取候选清单。”仍然保留
```

已重新构建 `apps/vulnfounder-cli/bin/openant`。当前 127.0.0.1:18080 进程仍在运行，为避免终止正在进行的 Claude 会话没有自动重启；结束当前会话后重启 Web 并强制刷新浏览器即可加载修复。

