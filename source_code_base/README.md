# VulnFounder 项目内源码仓库

这个目录是 VulnFounder 随项目一起使用的本地源码库根目录。每个一级子目录都是一个独立的 Git 仓库，例如：

```text
source_code_base/
├── communication_ipc/
├── drivers_hdf_core/
├── security_device_auth/
└── ...
```

## 使用约定

- 一级子目录保留各自的 `.git`、提交历史和 `origin` 远程地址；它们不是 VulnFounder 外层 Git 仓库中的普通源码文件。
- Web 已把这个目录作为项目内默认的源码仓库根目录，并允许通过 `OPENANT_SOURCE_CODE_BASE` 覆盖默认位置；CLI 的扫描命令仍可继续显式接收任意仓库路径。
- 增加新的源码仓库时，直接将它克隆到本目录下；不要把多个仓库合并成一个 Git 仓库。
- 本目录不保存 API 密钥、扫描结果或运行时配置。密钥仍应放在 VulnFounder 的配置目录中，并使用适当的文件权限保护。

当前目录中的仓库来自 OpenHarmony 社区代码，迁移清单和验证结果见：

`test_records/openharmony/OH-00D-project-local-source-code-base-2026-08-23.md`

仓库名称、相对路径和迁移时记录的 `origin` 见 `repositories.json`。这个文件是静态清单；实际分析前仍应以各子仓库当前 Git 状态为准。

Web 仓库下拉框只枚举本目录的一级独立 Git 仓库，不会递归进入仓库内部，也不会跟随一级符号链接。
