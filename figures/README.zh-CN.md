# OpenAnt 图形产物

这些图与当前项目流程保持同步，均提供 Mermaid 源码、Markdown 预览、PNG 位图和 SVG 矢量版。

| 图形 | 用途 |
| --- | --- |
| [openant-full-pipeline-flow.md](openant-full-pipeline-flow.md) | 当前实现的阶段级总览：源码定位、设备暴露面识别和普通静态扫描 |
| [openant-exposure-surface-flow.md](openant-exposure-surface-flow.md) | 独立暴露面识别的探测、用户确认启动、证据门禁和结果输出 |
| [openant-integrated-future-pipeline-flow.md](openant-integrated-future-pipeline-flow.md) | 后续整合预想：设备事实作为源码定位线索，再进入静态扫描 |

.mmd 是原始 Mermaid 源码；.png 适合直接插入文档；.svg 是可缩放的矢量图。
整合预想图中的虚线只表示规划中的证据关联，不代表当前版本已经自动串联阶段。

重新渲染示例：

~~~bash
npx -y @mermaid-js/mermaid-cli@latest \
  -i figures/openant-full-pipeline-flow.mmd \
  -o figures/openant-full-pipeline-flow.png \
  -b white --width 2400
~~~
