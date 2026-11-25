# 发布签名

## 当前固定签名身份

2026-11-25 起，本项目使用一把全新生成并固定保存的发布签名钥匙。原发布签名已停用；
2026-11-23 那轮轮换公布的指纹（`c8a20a…`）没有对应的可用私钥，已作废，不再被接受。
新钥匙仅保存在 Actions Secrets 和维护者受保护的备份中；后续构建继续使用同一把新钥匙，不自动生成或轮换。

- 从旧签名版本切换到新签名版本：先卸载旧 App，再安装新 APK。
- 安装新签名版本以后：后续新版本继续使用本页所列固定签名，按正常版本号规则覆盖升级。
- 应用包名保持 `com.gkeyes.lhasa26`；更换签名本身不改动当前分支的版本号。

当前固定发布证书的 SHA-256（公钥证书摘要，可公开）：

```text
bba588fabfdf9ed2b5652dc78b033822e1c39b162025be1d5e04e18e4f66bbac
```

## Actions Secrets

| Secret | 内容 |
|---|---|
| `LHASA_KEYSTORE_B64` | 当前固定 JKS keystore 的 base64 内容 |
| `LHASA_STORE_PASSWORD` | 当前 keystore 的存储密码 |
| `LHASA_KEY_ALIAS` | 当前发布私钥的 alias |
| `LHASA_KEY_PASSWORD` | 当前发布私钥的密码 |

四项必须同时配置。缺失、格式错误、密码或 alias 无效、证书摘要不匹配都会使 release 构建失败。
这些值不写入源码、工作树 properties 文件、日志、issue、构建产物或 Git 历史。

## CI 的签名流程

1. 仅允许受信 `main` / `next` 分支的 push 或手动工作流执行发布签名任务；PR 不执行这些任务。
2. 仅从上述四个 Secrets 读取签名材料，并以仅当前用户可读写的权限解码到 `$RUNNER_TEMP/lhasa26-signing/release.jks`。
3. 使用存储密码和 alias 导出公钥证书，核对本页的固定 SHA-256。
4. 将临时路径通过 `LHASA_KEYSTORE` 交给 Gradle；密码和 alias 只通过 job 环境变量提供。
5. Gradle 在 app release 任务前验证私钥可以解锁、证书符合当前固定身份；旧签名或任何其他签名均被拒绝。
6. 对最终 APK 运行 `apksigner verify --print-certs`，验证签名有效且只包含预期发布证书，之后才上传或发布。
7. 无论任务成功或失败，都清理临时签名文件。

`main` 与 `next` 使用同一套 Secrets 和同一个固定证书摘要。
工作流不读取仓库内的 keystore、`keystore.properties` 或旧提交，不存在自动新建钥匙、默认口令、默认 alias 或未签名发布回退。
`next` 仅缓存 Gradle 依赖和 wrapper，缓存不包含 `app/build`，也不恢复旧签名流程的缓存。

## 本地构建

Debug 构建不需要发布签名材料。release 构建需从受保护的备份取得当前固定 JKS，放在仓库外，
并在本地进程环境中设置以下四个名称：

- `LHASA_KEYSTORE`：当前 JKS 文件的绝对路径。
- `LHASA_STORE_PASSWORD`：当前存储密码。
- `LHASA_KEY_ALIAS`：当前 alias。
- `LHASA_KEY_PASSWORD`：当前私钥密码。

Gradle 会执行与 CI 相同的固定证书身份校验。不要把环境变量实际值写入命令历史、提交、日志或可分享的脚本。
本地 APK 对外提供前，仍须用 `apksigner verify --print-certs` 核对本页摘要。

## 历史签名

历史提交、旧标签和旧安装包可能仍对应已停用的旧签名；它们不再作为当前 release 构建的签名来源。
本次采用新签名建立后续固定升级身份，不再为保留旧签名而重写仓库历史。
当前 `main` / `next` 的构建门同时拒绝旧 keystore 和旧签名 APK，不能通过回退到历史文件绕过。

