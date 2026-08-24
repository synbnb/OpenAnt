# OpenAnt OpenHarmony 动态验证 Skill

## 任务目标

你正在 OpenAnt 生成的任务目录中工作。你的目标是根据 `context/candidate_manifest.json` 中的候选，检查静态结论是否能在真实 OpenHarmony 开发板上得到动态证据，并把每个候选的过程和结论写入 `results/<candidate-id>/`。

本任务使用 Claude Code 直接执行主机命令和 HDC，不使用 Docker。你可以阅读 `source_code/` 指向的真实源码，也可以使用上一级 `../openharmony-public-tools/` 中的公开工具库。不要把静态扫描结果当成事实；必须回到源码、构建配置和设备输出进行核对。

## 目录约定

```text
task/                                      # 当前 Claude Code 工作目录
├── CLAUDE.md                              # 本任务入口说明
├── context/
│   ├── candidate_manifest.json             # 待验证候选及筛选原因
│   ├── pipeline_output.json                # 完整静态流水线产物
│   ├── static_artifacts/                   # 同一扫描目录中的其他静态产物
│   └── source_code.json                    # 源码绝对路径和链接说明
├── source_code -> <真实源码目录>            # 可直接搜索的源码
├── results/                                # 只能在这里写动态验证结果
└── .claude/skills/openant-openharmony-dynamic/SKILL.md

../openharmony-public-tools/                # 任务目录的上一级公开工具库
```

## 必须先阅读的内容

1. `context/candidate_manifest.json`：确认候选 ID、Stage-2 verdict、CWE、入口函数和源码位置。
2. `context/pipeline_output.json`：了解完整 finding、调用图、保护条件和之前阶段的判断。
3. `context/static_artifacts/`：查找 dataset、unit context、入口索引、调用图、平台上下文和阶段报告。
4. `source_code.json` 与 `source_code/`：核对真实实现、构建目标、IDL/SA/profile、测试 client 和权限声明。
5. `../openharmony-public-tools/README.zh-CN.md`：确认工具路径、SDK API、HDC 版本和签名材料边界。

## 工作方式

对每个候选按以下顺序处理，不要跳过源码核验：

1. **候选审查**：从 finding 的文件/符号开始，向上查找注册入口、调用者和外部输入，再向下查找参数校验、权限检查和危险操作。若入口、协议或目标进程无法确认，写 `REQUIRES_PROTOCOL_REVIEW`，不要猜测 transaction 或字段。
2. **设备预检**：先运行 `../openharmony-public-tools/bin/hdc list targets -v`，固定设备序列号；记录设备 API level、系统版本、ABI、时间、SELinux 状态和目标服务/PID。设备不唯一或离线时写 `BLOCKED`。
3. **工具链检查**：使用公开工具库中的 HDC、Hvigor、Node 和 `hap-sign-tool.jar`。Hvigor 工程放在 ASCII 临时目录；不要把 `.p12`、私钥、密码或 API key 复制到任务目录。
4. **选择验证载体**：
   - HAP 公开系统服务 API：使用最小 HAP，直接在 HAP 中调用固定的公开、只读 API；不使用 TCP bridge，不连接 `faultloggerd` 私有 socket。
   - IPC/SA、HDF/HDI、Native 或私有 Unix socket：优先使用源码已有 proxy/client 或测试程序；使用 HDC/Native 适配器，并记录真实调用者 UID/PID/SELinux 身份。
   - `faultloggerd`：只读 SDK dump 可使用设备已有 `dumpcatcher -p`；不要自行拼接 crash/coredump 私有 payload。
5. **构建与校验**：先生成 unsigned 工件，再独立签名；记录构建命令摘要、SDK/API、unsigned/signed SHA-256、`verify-app` 输出和安装前 bundle 状态。Hvigor 自动签名失败与源码编译失败必须分开记录。
6. **部署与触发**：安装、启动、观察、停止必须是可审计步骤。HAP safe-smoke 先确认页面/Ability 生命周期；公开只读 API 可以在 safe-smoke 中执行一次。自定义 transaction、边界输入、私有 socket 和可能产生副作用的请求必须有明确候选证据后再执行。
7. **证据采集**：保存 HAP/Native stdout、stderr、退出码、HAP HiLog、服务 HiLog、faultlog、SELinux AVC、目标 PID、设备时间窗口和 HDC 返回值。`hilog -x` 可能包含历史日志，不能只按关键字命中判定本次行为。
8. **清理**：只停止本次启动的进程、删除本次创建的远端临时工件；不要卸载任务开始前已有的 bundle，不要清空历史日志，不要修改 `/system` 或关键服务。

## HAP 公开系统服务验证参考

OH-DYN-12 已在 API 23 开发板上验证了以下路径：

```text
HAP aboutToAppear
  → bundleManager.getBundleInfoForSelf()
  → faultLogger.querySelfFaultLog(FaultType.NO_SPECIFIC)
  → HAP HiLog + Faultlogger-napi 服务侧回调
  → aa force-stop
```

该路径返回过当前 bundle 信息和 10 条 FaultLogger 记录，但没有制造 crash/coredump。`@ohos.faultLogger` 在 SDK 中有 deprecated 警告，这应记录为兼容性事实，不应被误报成运行失败。

## 结果格式

每个候选必须创建：

```text
results/<candidate-id>/
├── verdict.json       # 机器可读结论
├── notes.md           # 给人看的源码、设备和因果分析
├── commands.jsonl     # 每条实际命令及退出码
├── stdout.log
├── stderr.log
└── evidence/          # hilog、faultlog、签名摘要、截图或其他证据
```

`verdict.json` 至少包含：

```json
{
  "candidate_id": "...",
  "status": "CONFIRMED|NOT_REPRODUCED|BLOCKED|INCONCLUSIVE|ERROR|REQUIRES_PROTOCOL_REVIEW",
  "entry_kind": "hap_public_api|ipc_sa|native|hdf_hdi|unix_socket|unknown",
  "source_evidence": [{"file": "...", "symbol": "...", "line": 0}],
  "device": {"serial": "...", "uid": "...", "pid": "..."},
  "causal_evidence": [],
  "limitations": [],
  "commands_log": "commands.jsonl"
}
```

只有输入确实抵达目标入口、目标行为发生在同一设备时间窗口、并且有 PID/服务日志/faultlog 等因果证据时，才能写 `CONFIRMED`。权限拒绝、服务不存在、API deprecated、单条异常日志或静态 finding 本身都不能单独确认漏洞。

## 重要约束

- 不使用 Docker，也不要为了兼容旧流程启动 `tcp_unix_bridge`。
- 不执行无限 fuzz、并发轰炸、随机未定义协议字节、root 切换、`hdc smode`、SELinux 修改或关键进程终止。
- 不把 API key、keystore、`.p12`、私钥密码或个人配置写入 `task/`、`results/` 或公开工具库。
- 所有结论必须可由任务目录中的源码引用、命令日志和设备证据复核。
