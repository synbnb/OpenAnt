# HAP 本地签名材料

动态验证需要签名 HAP 才能安装到开发板。本目录是本机受保护的签名材料
目录，不是用于提交到 Git 的证书仓库。项目内 OpenHarmony command-line-tools
还自带 SDK 测试根材料；未导入正式证书时，动态测试会按当前 HDC 设备 serial
临时生成设备绑定的 debug profile，不要求用户手工寻找 p7b 文件。

默认需要以下文件：

* `oh_release_chain.cer`：证书链；
* `oh_profile8.p7b`：签名 profile；
* `oh_release.p12`：私钥容器。

请将目录权限设为 `0700`，私钥容器设为 `0600`。也可以通过
`VULNFOUNDER_HAP_CERT_DIR` 指向其他受保护目录。设置页只展示文件是否存在、
权限是否合适和 SHA-256 摘要，不显示证书内容、私钥或密码。没有与开发板匹配
的正式签名材料时，系统优先使用项目内 SDK 测试根材料生成临时 profile；如果
工具链、Java、keytool 或 HDC serial 不完整，才会在签名前阻止构建并显示具体原因。
SDK 测试材料仅用于受控研究设备，不代表生产证书，也不会自动替代用户导入的 release
证书。
