# 项目内 LLM 配置

VulnFounder 默认优先读取同目录下的 `config.json`。该文件可以包含 API Key，
因此必须保持 `0600` 权限，并且已经被根目录 `.gitignore` 忽略。

首次配置可以复制模板：

```text
cp config/vulnfounder/config.example.json config/vulnfounder/config.json
chmod 600 config/vulnfounder/config.json
```

然后在 `llm_providers.autodl-openai` 中填入自己的 `api_key`。交付或提交
代码时只保留本模板，不要把真实密钥放入 Git、压缩包或公开仓库。

也可以通过 `VULNFOUNDER_CONFIG_FILE=/absolute/path/config.json` 临时指定其他
配置文件；该环境变量优先级最高。旧的 `OPENANT_CONFIG_FILE` 仍作为兼容
别名读取，但新脚本应使用 `VULNFOUNDER_CONFIG_FILE`。
