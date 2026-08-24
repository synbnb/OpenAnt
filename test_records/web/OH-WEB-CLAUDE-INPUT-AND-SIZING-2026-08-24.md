# OH Web Claude 对话输入与窗口尺寸修复记录

日期：2026-08-24

## 1. 问题现象

在动态测试的 Claude Code 面板中输入问题后，页面能看到“你”的消息，但随后出现的“Claude”内容只是同一段问题的终端回显，没有模型回答。终端窗口较窄时，Claude Code 的 Ink 界面还会发生文字挤压、换行和标签粘连。

## 2. 定位证据

排查了本次会话 `fb5cf7eefad58df6`：

- Web 会话接口记录到了输入事件和 PTY 输出事件；
- 输入内容在 PTY 输出中再次出现，说明它被终端回显了；
- Claude Code 进程的会话状态为 `idle`，没有进入处理用户消息的状态；
- 重启 Web 后该旧会话变为 `error`，新会话不会复用它。

因此，“Claude”标签下重复显示问题文本并不是模型回复，而是原始终端的回显。根因是 Web 后端向原始 PTY 写入了 `message + "\n"`。Claude Code 的交互终端把回车（`\r`）作为提交键；仅写换行会把文本留在输入缓冲区，导致消息没有真正提交。

## 3. 修改内容

### 3.1 Claude 消息提交

`apps/openant-cli/internal/server/claude_session.go` 的 PTY 写入改为：

```text
message + "\r"
```

这样 Web 输入会等价于用户在 Claude Code 终端按下 Enter，才会触发模型处理。

### 3.2 PTY 初始尺寸

Claude Code 启动后设置 PTY 尺寸为 160 列、48 行，避免默认小终端导致 Ink 界面折叠和字体挤压。

### 3.3 Web 对话面板

- 对话区在桌面端扩大到至少 420px 高，并按视口高度自适应，最高 720px；
- 对话字体、行距、消息内边距和输入框高度适当增大；
- 右侧任务目录浏览区同步扩大；
- 移动端使用单独的较小高度规则；
- Claude 面板仍只在“动态测试”阶段显示，不再出现在所有阶段菜单下。

## 4. 测试记录

执行目录：`/Users/shiyu/学习/hyl/new/OpenAnt/apps/openant-cli`

```text
GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go test ./internal/server
```

结果：通过。

```text
GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go test -race ./internal/server
```

结果：通过。新增测试验证 PTY 写入内容以 `\r` 结尾。

```text
node --check <(awk 'BEGIN{p=0} /<script>/{p=1;next} /<\\/script>/{p=0} p' apps/openant-cli/ui/scan.html)
```

结果：通过。

```text
GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go build -o bin/openant .
```

结果：通过。

Web 已重启并确认 `http://127.0.0.1:18080/` 返回 HTTP 200；历史扫描详情页加载了新的对话区尺寸和动态测试阶段绑定规则。

## 5. 复测方式

旧的 `fb5cf7eefad58df6` 会话是在修复前创建的，重启后已停止，不能用于验证新输入逻辑。请重新发起一次启用 Claude Code 动态测试的扫描，在动态测试页面发送一句短消息，例如：

```text
请列出当前任务目录中的候选漏洞文件名。
```

预期结果：页面先显示用户消息，随后显示 Claude 的实际处理过程和回答，而不是只重复用户输入。若仍出现重复回显，应记录新会话 ID，以便继续检查 PTY 输入和 Claude 会话状态。
