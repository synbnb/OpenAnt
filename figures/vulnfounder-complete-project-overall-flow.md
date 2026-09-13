# VulnFounder 完整项目总流程图

该图展示设备资产发现、单目标暴露面识别、源码定位、仓库/范围确认、静态分析、验证和报告的当前总体关系。虚线表示可选路径或下一轮反馈，不表示候选事实已经成为严格调用关系。

```mermaid
flowchart TB
    U["用户目标"]
    A1["开发板资产发现<br/>列举全部 Socket 暴露面"]
    A2["单目标暴露面识别<br/>Unix / TCP / UDP"]
    A3["OpenHarmony 源码定位<br/>OpenGrok + 证据归因"]
    A4["仓库与版本确认<br/>用户批准后拉取"]
    A5["Socket 服务扫描范围确认<br/>模型调查 + 用户选择"]
    B1["本地源码仓库"]
    S1["解析与平台画像"]
    S2["统一调用事实与有效调用图"]
    S3["可达性分层<br/>strict / candidate / fallback"]
    S4["应用安全上下文与入口路径源码"]
    S5["上下文增强"]
    S6["Stage 1 初步安全分析"]
    S7["Stage 2 证据复核<br/>可选"]
    S8["动态验证<br/>可选"]
    S9["标准结果、中文/英文报告与披露"]
    O1[("设备资产库")]
    O2[("定位会话与 source_handoff")]
    O3[("扫描会话全量阶段产物")]
    F["人工复核、评测与新事实反馈"]

    U -->|"不知道设备上有哪些端点"| A1
    A1 --> O1
    O1 -->|"选择一个端点"| A2
    U -->|"已知端点名称"| A2
    A2 -->|"设备事实"| A3
    U -->|"只做源码定位"| A3
    A3 --> A4 --> O2
    O2 --> A5
    U -->|"已有仓库"| B1
    A4 --> B1
    A5 -->|"scan_scope.json"| B1
    B1 --> S1 --> S2 --> S3 --> S4 --> S5 --> S6
    S6 --> S7 --> S8 --> S9 --> O3
    S6 -. "Stage 2 关闭" .-> S9
    S7 -. "动态验证关闭" .-> S9
    O3 --> F
    F -. "候选事实与回归样本" .-> S2
```

PNG 预览：[vulnfounder-complete-project-overall-flow.png](vulnfounder-complete-project-overall-flow.png)
