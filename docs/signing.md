# 发布签名

## 固定签名身份

本项目继续使用原来的发布签名钥匙。迁移只改变签名材料的保存与读取方式，不生成新钥匙。
覆盖升级还需满足 Android 对应用 ID、签名和版本号的校验。

固定发布证书的 SHA-256（公钥证书摘要，可公开）：

```text
3317c15bb094220efb3c61efeb88b7443b3acbe76fcb98566c940ae0a961aa89
```

## Actions Secrets

| Secret | 内容 |
|---|---|
| `LHASA_KEYSTORE_B64` | 原发布 keystore 文件的 base64 内容 |
| `LHASA_STORE_PASSWORD` | 原 keystore 的存储密码 |
| `LHASA_KEY_ALIAS` | 原发布私钥的 alias |
| `LHASA_KEY_PASSWORD` | 原发布私钥的密码 |

这些值只保存在 Actions Secrets 或维护者的受保护备份中，不写入源码、日志、issue、构建产物或 Git 历史。
不在文档中提供私钥、密码及其编码值。

## CI 的签名流程

1. 仅从上述四个 Secrets 读取签名材料；缺失任一项立即失败。
2. 以仅当前用户可读写的权限，将 keystore 解码到 `$RUNNER_TEMP/lhasa26-signing/release.jks`。
3. 使用配置的存储密码和 alias 导出公钥证书，并核对上述 SHA-256；格式、密码、alias 或证书不符即失败。
4. 将临时文件路径通过 `LHASA_KEYSTORE` 交给 Gradle；其余三个值通过同名环境变量传入。
5. Gradle 对 app release 任务检查四个签名环境变量和 keystore 文件；签名密码错误会使签名任务失败。
6. 对最终 APK 运行 `apksigner verify --print-certs`，要求签名有效且只有预期发布证书的摘要，之后才上传或发布。
7. 无论任务成功或失败，都清理临时签名文件。

CI 不从仓库文件、`keystore.properties` 或旧提交恢复签名，也不在缺失时新建、提交钥匙或发布未签名 APK。
`main` 与 `next` 使用同一套 Secrets、同一个固定证书摘要。

## 本地构建

Debug 构建不需要发布签名材料。构建 release 时，维护者须从受保护的备份取得原 keystore，
放在仓库外，并在本地进程环境中设置以下四个名称：

- `LHASA_KEYSTORE`：原 keystore 文件的绝对路径。
- `LHASA_STORE_PASSWORD`：原存储密码。
- `LHASA_KEY_ALIAS`：原 alias。
- `LHASA_KEY_PASSWORD`：原私钥密码。

Gradle 不读取仓库中的签名 properties 文件，也没有默认密码或默认 alias。
不要把环境变量的实际值写入命令历史、提交、日志或可分享的构建脚本。
本地 APK 对外提供前，同样使用 `apksigner verify --print-certs` 核对上面的固定证书摘要。

## 历史材料的清理

`.gitignore` 仅阻止新文件被普通方式加入 Git，不能移除已跟踪文件或历史对象。
私钥和含密码的配置必须从所有拟公开分支及标签中清除；还需单独核实历史 PR 引用、旧提交缓存和旧产物，
确认 GitHub 不再向公开访问者提供这些签名材料后，才能公开原仓库。

