# OpenHarmony Command Line Tools 6.1.0.860

这是动态验证真机冒烟测试使用的本地工具链清单。工具链已经解压到当前项目内，运行时不依赖 `/private/tmp` 中的 HDC 或 SDK。

## 来源与校验

| 项目 | 值 |
|---|---|
| 原始压缩包 | `/Users/shiyu/Downloads/commandline-tools-mac-arm64-6.1.0.860.zip` |
| SHA-256 | `72cd62961da151f175d2bf499547663011307116e39521fd855faef1a0cfbc13` |
| 平台 | macOS ARM64 |
| 工具链版本 | 6.1.0.860 |
| HarmonyOS SDK | 6.1.0 Release，API 23 |
| 内置 HDC | 3.2.0c |

## 项目内路径

```text
libs/openant-core/utilities/dynamic_tester/
└── toolchains/
    └── commandline-tools-mac-arm64-6.1.0.860/
        └── command-line-tools/
            ├── sdk/
            └── tool/
```

HDC 的实际路径为：

```text
libs/openant-core/utilities/dynamic_tester/toolchains/commandline-tools-mac-arm64-6.1.0.860/command-line-tools/sdk/default/openharmony/toolchains/hdc
```

该目录约 6GB，因此已加入 `.gitignore`，但不会从本地项目删除。交付压缩包时可以按本清单把该目录一并打包；如果通过 Git 克隆交付，则需要在发布包中另行附带工具链。

## 当前验证范围

- `hvigorw tasks` 能识别 API 23 OpenHarmony SDK；
- ArkTS、资源和 HAP 打包成功；
- `hap-sign-tool.jar` 能对 API 23 HAP 完成签名和校验；
- 内置 HDC 能连接设备、安装 HAP、启动并停止 Ability。

本工具链清单不保存任何私钥。真机签名使用的授权材料由运行环境单独提供，测试产物目录只保留已签名 HAP 和公开证书链。
