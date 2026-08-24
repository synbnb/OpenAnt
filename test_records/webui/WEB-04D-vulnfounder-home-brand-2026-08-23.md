# WEB-04D：首页品牌文案调整

日期：2026-08-23  
范围：首页展示文案  
状态：已完成

## 修改内容

- 首页 `<title>`、品牌名称由 `OpenAnt` 改为 `vulnfounder`。
- 品牌标识由 `OA` 调整为 `VF`。
- 删除“从源码入口追踪安全风险”标题及其英文翻译键。
- 首页说明文案中的产品名同步改为 `vulnfounder`。
- 保留 `openant setup llm` 命令提示和 `openant.ui.language` 内部存储键，它们属于功能/兼容标识，不是首页品牌展示。

## 测试记录

1. 首页内嵌 JavaScript：`node --check --input-type=commonjs` 通过。
2. Web 模板回归：

   ```bash
   GOCACHE=/private/tmp/openant-go-build \
   GOMODCACHE=/private/tmp/openant-go-mod \
     ../../.devtools/go1.25.7/go/bin/go test ./internal/server
   ```

   结果：通过；新增测试 `TestHomeBrandUsesVulnFounderAndOmitsEntryRiskTagline`。
3. 重建并重启 Web 后，访问 `http://127.0.0.1:18080/` 实际检查到：
   - `<title>vulnfounder 源码安全扫描</title>`；
   - 首页显示 `<h1>vulnfounder</h1>`；
   - 不再包含“从源码入口追踪安全风险”。
