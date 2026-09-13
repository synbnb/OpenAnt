# VulnFounder Claude Code 动态验证任务

这是一个 OpenHarmony 开发板动态验证任务目录。请先阅读：

1. `.claude/skills/vulnfounder-openharmony-dynamic/SKILL.md`
2. `context/candidate_manifest.json`
3. `context/pipeline_output.json`
4. `../openharmony-public-tools/README.zh-CN.md`

任务目标、候选清单、源码路径和工具路径都由 VulnFounder 在 `task_manifest.json` 中记录。动态验证结果只能写入 `results/`，不要修改 `context/`、扫描原始产物或源码仓库中的文件。

本任务允许直接使用主机命令和 HDC，不使用 Docker。先做源码核验和设备预检，再按 Skill 中的 HAP、IPC/SA、Native、HDF/HDI 或 Unix socket 流程执行。所有设备操作、构建、签名和清理命令都必须保存到对应候选的 `commands.jsonl`。

完成后确认：

- 每个候选都有 `results/<candidate-id>/verdict.json` 和 `notes.md`；
- 结论状态属于 Skill 规定的枚举；
- 证据包含源码位置、设备序列号、调用者身份、目标 PID 和时间窗口；
- 没有把私钥、密码、API key 或未经脱敏的敏感数据写入结果；
- `results/summary.json` 汇总所有候选，并指出未执行原因和局限性。
