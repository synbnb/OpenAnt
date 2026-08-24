# WEB-04A Web 外壳与中英文切换测试记录

- 日期：2026-08-23
- 阶段：WEB-04A
- 范围：首页、扫描详情页、中英文界面状态、响应式基础布局
- 不在本阶段范围：阶段产物语义说明、JSON 友好视图、入口函数列表、可伸缩调用图

## 1. 修改前逻辑

1. 首页和扫描详情页分别在 HTML 中写死英文文案。
2. 首页以两栏卡片展示扫描表单和简单流程说明。
3. 扫描详情页使用顶部横向胶囊显示九个阶段。
4. 阶段报告直接输出原始 JSON，产物列表只展示文件名、类别和原始文件链接。
5. 页面没有跨页面保存的语言选择状态。
6. 首页模板中存在两个相同的“Start Scan”提交按钮。

## 2. 修改后逻辑

1. 首页和扫描详情页默认使用中文，并提供“中文 / English”选择器。
2. 语言状态保存在浏览器的 \`localStorage\` 键 \`openant.ui.language\` 中，进入另一个页面后继续使用相同语言。
3. 页面保留现有 Go 模板、路由、表单字段、CSRF、SSE、pipeline 和 artifact 接口，不增加前端构建依赖。
4. 首页改为扫描流程说明侧栏与扫描工作区的布局；扫描详情页改为左侧阶段轨道与右侧运行内容区。
5. 增加 1024、768 和 420 像素附近的显式响应式布局，并支持 \`prefers-reduced-motion\`。
6. 增加清晰的运行中、完成、失败、空结果、加载中和连接断开文案。
7. 旧版 Anthropic Key 文案仍受服务端条件控制；使用 OpenAI 配置时不会把该兼容字段或文案渲染到页面。
8. 删除重复的扫描提交按钮，只保留一个主操作。

## 3. 修改文件

- \`apps/openant-cli/ui/index.html\`
- \`apps/openant-cli/ui/scan.html\`
- \`apps/openant-cli/internal/server/ui_i18n_test.go\`

## 4. 自动化测试

### 4.1 Web 模板专项测试

命令：

\`\`\`bash
env GOCACHE=/Users/shiyu/学习/hyl/new/OpenAnt/.devtools/gocache \
  GOPATH=/Users/shiyu/学习/hyl/new/OpenAnt/.devtools/gopath \
  /Users/shiyu/学习/hyl/new/OpenAnt/.devtools/go1.25.7/go/bin/go test ./internal/server
\`\`\`

结果：

\`\`\`text
ok github.com/knostic/open-ant-cli/internal/server
\`\`\`

专项测试覆盖：

- 两个模板可被 Go \`html/template\` 正常解析。
- 两个页面均包含中文和英文选项。
- 两个页面均使用同一个持久化语言键。
- 扫描表单的关键字段和 CSRF 字段保持不变。
- 九个 pipeline 阶段仍完整存在。
- SSE 日志、pipeline API 和 artifacts API 调用仍存在。
- 首页只有一个扫描提交按钮。
- 响应式和 reduced-motion 样式存在。
- 可见页面源码不包含长破折号字符。

### 4.2 OpenAnt CLI 全量 Go 测试

首次在受限沙箱运行时，\`cmd/llm_probe_test.go\` 的 \`httptest\` 临时监听被操作系统拒绝，错误为：

\`\`\`text
listen tcp6 [::1]:0: bind: operation not permitted
\`\`\`

随后在允许本机回环监听的执行环境中运行同一命令：

\`\`\`bash
env GOCACHE=/Users/shiyu/学习/hyl/new/OpenAnt/.devtools/gocache \
  GOPATH=/Users/shiyu/学习/hyl/new/OpenAnt/.devtools/gopath \
  /Users/shiyu/学习/hyl/new/OpenAnt/.devtools/go1.25.7/go/bin/go test ./...
\`\`\`

结果：全部通过。

\`\`\`text
ok github.com/knostic/open-ant-cli/cmd
ok github.com/knostic/open-ant-cli/internal/checkpoint
ok github.com/knostic/open-ant-cli/internal/config
ok github.com/knostic/open-ant-cli/internal/git
ok github.com/knostic/open-ant-cli/internal/languages
ok github.com/knostic/open-ant-cli/internal/models
ok github.com/knostic/open-ant-cli/internal/output
ok github.com/knostic/open-ant-cli/internal/python
ok github.com/knostic/open-ant-cli/internal/report
ok github.com/knostic/open-ant-cli/internal/server
\`\`\`

### 4.3 JavaScript 与差异检查

执行内容：

- 使用 Node.js 25.9.0 对两个 HTML 中的内联 JavaScript 执行语法检查。
- 对本阶段三个文件执行 \`git diff --check\`。

结果：全部通过，无 JavaScript 语法错误，无尾随空格或补丁格式错误。

### 4.4 真实 HTTP 页面检查

重新构建 CLI 后，将 Web 服务启动在：

\`\`\`text
http://127.0.0.1:18080
\`\`\`

验证结果：

- \`GET /\` 返回 \`200 OK\`。
- 首页响应包含语言选择器、中文首页标题、\`source_code_base\` 仓库说明和唯一的开始扫描按钮。
- \`GET /scan/013e20e503ce1b29\` 返回新版扫描详情页。
- 扫描详情页包含九个阶段、运行日志、阶段数据、扫描产物和 SSE \`EventSource\`。
- \`X-Frame-Options: DENY\`、\`Cross-Origin-Resource-Policy: same-origin\` 和 \`X-Content-Type-Options: nosniff\` 保持生效。

### 4.5 主要颜色对比度

| 用途 | 对比度 | 结论 |
|---|---:|---|
| 主按钮文字与背景 | 7.05:1 | 通过 WCAG AA |
| 正文与页面背景 | 15.16:1 | 通过 WCAG AA |
| 次要文字与白色背景 | 6.47:1 | 通过 WCAG AA |

## 5. 当前结论

WEB-04A 已通过。中英文切换、跨页面语言持久化、基础排版、响应式状态和原有扫描交互均可用。

下一个建议阶段是 WEB-04B：为九个阶段补充可点击菜单、阶段目的/输入/输出说明，并将每个产物明确归属到对应阶段。
