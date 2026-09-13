# VulnFounder 图形产物

这些图与当前项目流程保持同步，均提供 Mermaid 源码、Markdown 预览、PNG 位图和 SVG 矢量版。

| 图形 | 用途 |
| --- | --- |
| [vulnfounder-full-pipeline-flow.md](vulnfounder-full-pipeline-flow.md) | 当前实现的阶段级总览：源码定位、设备暴露面识别和普通静态扫描 |
| [vulnfounder-exposure-surface-flow.md](vulnfounder-exposure-surface-flow.md) | 独立暴露面识别的探测、用户确认启动、证据门禁和结果输出 |
| [vulnfounder-integrated-future-pipeline-flow.md](vulnfounder-integrated-future-pipeline-flow.md) | 后续整合预想：设备事实作为源码定位线索，再进入静态扫描 |
| [vulnfounder-complete-project-overall-flow.md](vulnfounder-complete-project-overall-flow.md) | 当前项目从设备资产、源码定位到分析报告的完整总流程 |
| [vulnfounder-system-runtime-architecture.md](vulnfounder-system-runtime-architecture.md) | Web、Go 控制平面、Python Agent 平面、外部事实源与存储边界 |
| [vulnfounder-exposure-location-integrated-flow.md](vulnfounder-exposure-location-integrated-flow.md) | 设备资产、单目标识别、源码定位、用户确认与 Git 交接 |
| [vulnfounder-repository-scan-detailed-flow.md](vulnfounder-repository-scan-detailed-flow.md) | 仓库解析、有效图、可达性、Stage 1/2、动态验证与报告 |
| [vulnfounder-evidence-and-feedback-loop.md](vulnfounder-evidence-and-feedback-loop.md) | 原生图、严格/候选事实、入口血缘和分析反馈闭环 |

.mmd 是原始 Mermaid 源码；.png 适合直接插入文档；.svg 是可缩放的矢量图。
整合预想图中的虚线只表示规划中的证据关联，不代表当前版本已经自动串联阶段。

重新渲染示例：

~~~bash
npx -y @mermaid-js/mermaid-cli@latest \
  -i figures/vulnfounder-full-pipeline-flow.mmd \
  -o figures/vulnfounder-full-pipeline-flow.png \
  -b white --width 2400
~~~
