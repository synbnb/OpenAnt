# OpenHarmony 版本切换风险清单

| 编号 | 风险 | 证据/位置 | 影响 | 建议 |
| --- | --- | --- | --- | --- |
| V-01 | 7.0 OpenGrok 与 6.1 Manifest/目标 revision 混用 | `config/vulnfounder/config.json:24,39-40`；Go 默认值 `apps/vulnfounder-cli/internal/config/runtime_settings.go:21-28` | 仓库归属、revision 校验和拉取候选错误或进入 VERSION_MISMATCH | 建立 7.0 Manifest，更新配置和默认值；确认 project 名称后再定位 |
| V-02 | 旧源码证据/定位会话被续用 | 证据、clone、候选版本和 session 产物按会话保存，旧会话不会自动知道新索引 | 7.0 结果引用 6.1 行号、映射或源码哈希 | 7.0 使用全新 session/产物根；旧 session 只读归档并标旧版本 |
| V-03 | Clang 事实依赖旧构建上下文 | `config` 无完整编译上下文；扫描器会显式生成 `no_compile_commands` | 类型绑定、间接边和宏分支结果不可代表 7.0 产品配置 | 重新取得 7.0 compile database/自动重建上下文；保存宏、sysroot、生成头文件指纹 |
| V-04 | 运行时清单仍是 6.1 | `runtime/openharmony/manifest.example.json:3`；`runtime/openharmony/macos-arm64-6.1/manifest.json:3`；`fixtures/hap_smoke_app/local.properties` | HDC/Hvigor/Node/签名工具与 7.0 设备不匹配，HAP 安装或执行失败 | 导入匹配主机和 7.0 的 command-line-tools，更新 manifest，不跨平台复用 macOS 包 |
| V-05 | HAP/协议描述符使用 6.1 假设 | `protocols/descriptors.py` 中证据写明 6.1 实测；生成合同和模板由旧样本驱动 | 合法探测、字段解析、权限和 oracle 在 7.0 上误判 | 每个 descriptor 带源码/设备版本指纹，7.0 重新合法自证；旧描述符只作历史版本 |
| V-06 | 板端 ABI 与 native 编译器可能不匹配 | `utilities/openharmony_dynamic/native/build.py:3,23` 注释与实际 `aarch64` 路径不一致 | 交叉编译出的二进制无法在 RK3568 32 位系统运行 | 先读取设备 ABI，再选择 armv7/aarch64 编译器和 sysroot |
| V-07 | 设备事实只按 serial 持久化 | `agent/device_facts.py:21-33` 文件名只含 serial 前缀；预检虽有 version_check，但事实库未按版本分区 | 刷到 7.0 后沿用 6.1 稳定 Socket/协议事实 | 版本变化自动失效或按 serial+build fingerprint 分库，7.0 重新全量枚举 |
| V-08 | 旧历史样本被误当成 7.0 漏洞 | 评测样本和 contracts 含 6.1 路径、行号和实机说明 | “修复后不存在”被误报为检测失败，或将已修复问题提交为新问题 | 重新建立 7.0 ground truth；历史样本单列回归/负例，不直接合并指标 |
| V-09 | 报告版本元数据仍可能来自旧输入 | 报告生成器支持 `release_version`，但版本由输入 metadata 提供 | 报告中的受影响版本与实际源码/设备不一致 | 报告必须同时记录 target revision、源码 commit、设备 fingerprint、工具链清单 |
| V-10 | 配置/凭据风险与版本切换无关但需顺手处理 | 本地 `config/vulnfounder/config.json` 含 API key 字段 | 交付或提交时泄露凭据 | 旋转已暴露密钥，配置只保留环境变量引用；不要把密钥写入分析产物 |

## 风险判定口径

- V-01～V-05、V-07、V-08 是 7.0 切换前的阻断项。
- V-06 取决于当前开发板 ABI，但在动态测试前必须核实。
- V-09 是报告质量阻断项，不一定阻止扫描运行。
- V-10 是独立的凭据卫生问题，不应被误称为版本兼容性问题。
