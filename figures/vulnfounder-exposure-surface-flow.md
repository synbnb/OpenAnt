# OpenHarmony 暴露面识别流程图

这张图聚焦独立的设备侦查阶段：先以受限命令采集事实，再由可选的大模型进行字段归纳。所有字段都必须能回指设备证据；服务未启动时，启动和重新侦查必须经过用户确认。

![OpenHarmony 暴露面识别流程图](vulnfounder-exposure-surface-flow.png)

```mermaid
%%{init: {"theme": "base", "themeVariables": {"fontFamily": "Arial, sans-serif", "fontSize": "15px", "primaryTextColor": "#17202A"}, "flowchart": {"htmlLabels": true, "curve": "linear", "nodeSpacing": 34, "rankSpacing": 46}}}%%
flowchart TD
    start(["输入服务名或 Socket"])
    normalize["目标标准化<br/>识别路径、服务名和设备"]
    choose["选择开发板与 HDC 连接"]
    probe["固定探测计划<br/>Socket、进程、权限、SELinux、配置"]
    facts["设备事实与字段证据<br/>stdout、退出码、时间、截断标志"]
    state{"是否发现运行中的端点？"}
    extract["LLM 语义提取（可选）<br/>只在已采集事实中归纳字段"]
    configured["发现配置但当前未启动"]
    confirm{"用户同意临时启动？"}
    recheck["重新读取配置与参数<br/>确认仍是 0 → 1"]
    startService["执行固定启动参数<br/>不接受模型或用户自定义命令"]
    reprobe["启动后重新只读侦查"]
    evidenceGate["证据门禁<br/>无证据字段保留未知"]
    result["结构化暴露面结果<br/>类型、状态、进程、DAC、SELinux、风险"]
    audit["审计产物与 Web 展示"]
    partial["部分结果或可恢复错误<br/>保留已采集事实"]

    start --> normalize --> choose --> probe --> facts --> state
    state -->|"是"| extract
    state -->|"否，但找到服务配置"| configured --> confirm
    state -->|"未找到端点或配置"| partial
    confirm -->|"拒绝"| extract
    confirm -->|"同意"| recheck
    recheck -->|"通过"| startService --> reprobe --> probe
    recheck -->|"配置变化、参数异常或失败"| partial
    extract --> evidenceGate
    evidenceGate --> result --> audit
    partial --> audit

    classDef start fill:#E8F1FF,stroke:#2F6BFF,stroke-width:2px,color:#17315C
    classDef process fill:#F7F9FC,stroke:#64748B,stroke-width:1.2px,color:#17202A
    classDef decision fill:#FFF4D6,stroke:#C98A00,stroke-width:1.5px,color:#5C4100
    classDef model fill:#F1EAFE,stroke:#815AC7,stroke-width:1.5px,color:#38215F
    classDef output fill:#E8F7EE,stroke:#2E8B57,stroke-width:1.5px,color:#164B2D
    classDef warning fill:#FFF0F0,stroke:#C94C4C,stroke-width:1.5px,color:#6B2020

    class start start
    class normalize,choose,probe,facts,recheck,startService,reprobe process
    class state,confirm decision
    class extract model
    class result,audit output
    class configured,partial warning
```

## 输出重点

- 运行中的端点会关联 Socket 类型、进程、UID、DAC 权限和 SELinux 标签等字段。
- 已配置但未启动的服务不会被自动启动；用户拒绝时保留停止状态和已采集信息。
- 大模型只负责解释结构化探测结果，不生成任意 HDC 命令，也不能覆盖字段级证据。
- 命令失败、设备离线或字段无法确认时，结果标记为部分完成并保留未知值及审计信息。
