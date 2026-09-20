# WEB-04B 阶段菜单与产物说明测试记录

- 日期：2026-08-23
- 阶段：WEB-04B
- 范围：阶段说明元数据、阶段菜单、按阶段过滤产物、产物详细说明
- 不在本阶段范围：JSON 结构化查看器、入口函数列表、可伸缩调用图

## 1. 修改前逻辑

1. Pipeline API 只提供阶段 ID、英文名称、状态和执行统计。
2. Artifact API 只提供文件名、英文标签和粗粒度类别。
3. 扫描详情页的阶段轨道只用于显示状态，不能点击选择。
4. 所有产物混在同一个列表中，无法直接判断由哪个阶段生成。
5. 阶段报告以多个原始 JSON 折叠框平铺展示，缺少目的、输入和输出解释。

## 2. 修改后逻辑

1. Pipeline API 为九个阶段增加：
   - 目的说明；
   - 输入列表；
   - 输出列表；
   - 是否属于可选阶段。
2. Artifact API 为每个白名单产物增加：
   - 所属阶段；
   - 文件用途说明。
3. 左侧九个阶段改为可点击菜单，并使用标准 tab / tabpanel 无障碍语义。
4. 支持方向键、Home 和 End 键切换阶段。
5. 扫描运行期间，如果用户尚未手动选择阶段，页面会自动跟随当前执行阶段；用户手动选择后不再抢占视图。
6. 每个阶段详情独立显示：
   - 阶段目的；
   - 阶段输入；
   - 预期输出；
   - 当前状态；
   - 耗时；
   - 模型 token；
   - 模型费用；
   - 是否可选；
   - 错误信息；
   - 原始阶段 JSON。
7. 产物列表按当前阶段过滤，每个文件显示中文名称、详细用途、类别、大小、更新时间和原始文件入口。
8. 中英文切换会同步更新阶段说明、输入输出、状态和产物说明。

## 3. 阶段与主要产物映射

| 阶段 | 主要产物 |
|---|---|
| parse | \`parse.report.json\`、\`platform_profile.json\`、\`dataset.json\`、\`analyzer_output.json\`、\`call_graphs.json\` |
| app-context | \`app-context.report.json\`、\`application_context.json\` |
| llm-reachability | \`llm-reachability.report.json\`、\`llm_reachability.json\` |
| enhance | \`enhance.report.json\`、\`dataset_enhanced.json\` |
| analyze | \`analyze.report.json\`、\`results.json\` |
| verify | \`verify.report.json\`、\`results_verified.json\` |
| build-output | \`build-output.report.json\`、\`pipeline_output.json\` |
| dynamic-test | \`dynamic-test.report.json\`、\`dynamic_test_results.json\`、\`dynamic_test_results.md\` |
| report | \`report.report.json\`、\`scan.report.json\`，以及原有独立 HTML、摘要和披露报告路由 |

## 4. 修改文件

- \`apps/vulnfounder-cli/internal/server/server.go\`
- \`apps/vulnfounder-cli/internal/server/pipeline_test.go\`
- \`apps/vulnfounder-cli/internal/server/artifact_test.go\`
- \`apps/vulnfounder-cli/internal/server/ui_i18n_test.go\`
- \`apps/vulnfounder-cli/ui/scan.html\`

## 5. 测试结果

### 5.1 Web Server 专项测试

命令：

\`\`\`bash
env GOCACHE=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/gocache \
  GOPATH=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/gopath \
  /Users/shiyu/学习/hyl/new/VulnFounder/.devtools/go1.25.7/go/bin/go test ./internal/server
\`\`\`

结果：

\`\`\`text
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server
\`\`\`

新增或扩展的断言包括：

- Pipeline API 返回非空阶段说明、输入和输出。
- LLM reachability、verify 和 dynamic-test 被标记为可选阶段。
- Artifact API 返回正确的阶段归属和非空用途说明。
- 所有白名单产物名称唯一。
- 所有白名单产物必须归属于九个有效阶段之一。
- 所有白名单产物必须具有用途说明。
- 页面具有 tablist、tab、tabpanel、aria-selected 和 aria-controls 语义。
- 页面具有阶段点击、按键切换、产物阶段过滤和原始 JSON 入口。

### 5.2 VulnFounder CLI 全量 Go 测试

命令：

\`\`\`bash
env GOCACHE=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/gocache \
  GOPATH=/Users/shiyu/学习/hyl/new/VulnFounder/.devtools/gopath \
  /Users/shiyu/学习/hyl/new/VulnFounder/.devtools/go1.25.7/go/bin/go test ./...
\`\`\`

结果：全部通过。

\`\`\`text
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/cmd
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/checkpoint
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/config
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/git
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/languages
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/models
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/output
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/python
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/report
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server
\`\`\`

### 5.3 前端脚本与补丁检查

- 使用 Node.js 25.9.0 对扫描详情页内联 JavaScript 执行语法检查：通过。
- 对本阶段源码执行 \`git diff --check\`：通过。
- Go 文件执行 \`gofmt\`：通过。

### 5.4 运行服务检查

新版二进制已经重新构建，Web 服务运行在：

\`\`\`text
http://127.0.0.1:18080
\`\`\`

服务启动成功。重启后当前 Web 输出目录没有可恢复的历史扫描，因此旧扫描 ID 返回 404；没有为展示页面而伪造扫描记录，也没有触发真实模型扫描。真实 API 数据结构由上述 \`httptest\` 自动化测试覆盖。

## 6. 当前结论

WEB-04B 已通过。九个阶段已经成为独立菜单，每个阶段能解释自身逻辑并只展示属于自己的文件产物。用户仍可查看原始阶段 JSON 和原始产物文件。

下一建议阶段是 WEB-04C：实现原始 JSON 与结构化友好视图的切换，为平台画像、应用上下文、数据集、分析结果和验证结果提供专用摘要视图。
