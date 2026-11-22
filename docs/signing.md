# 签名与 Secrets

## 为什么不能随便换钥匙

Android 用签名标识 App 的身份：

- **同一个签名** → 新版能覆盖安装，应用内设置、导出目录都保留；
- **换了签名** → 系统当成另一个 App，装不上去，必须先卸载旧包（应用内设置丢失）。

所以这里**保留同一把钥匙**（`keystore/lhasa26.jks`，alias `lhasa26`），
不做密钥轮换。要修的只是两件卫生问题：jks 不该出现在工作树里，口令不该写进脚本。

## 现在的做法

| 项 | 位置 |
|---|---|
| keystore 文件 | GitHub Secret `LHASA_KEYSTORE_B64`（base64 后的 jks） |
| store 口令 | Secret `LHASA_STORE_PASSWORD` |
| key 口令 | Secret `LHASA_KEY_PASSWORD` |
| key alias | Secret `LHASA_KEY_ALIAS`（值是 `lhasa26`） |

`app/build.gradle.kts` 只认环境变量：`LHASA_KEYSTORE`（路径）、`LHASA_STORE_PASSWORD`、
`LHASA_KEY_ALIAS`、`LHASA_KEY_PASSWORD`。任何一个缺失时，release **不签名**并在日志里说明，
绝不回退到硬编码口令。

CI 的 `build.yml` 在构建前用 `LHASA_KEYSTORE_B64` 还原出 `keystore/lhasa26.jks`。

## 怎么拿到 jks 并生成 base64

jks 已经从工作树移除，但仍在这份历史里：

```sh
# 在任意有 git 的机器上克隆仓库后
git log --oneline -- keystore/lhasa26.jks          # 找到删除前的提交
git show <那个提交>:keystore/lhasa26.jks > lhasa26.jks

# 生成 Secret 用的一行 base64（不要换行）
base64 -w0 lhasa26.jks
```

手机上也可以：在 GitHub 网页打开删除前的那次提交里的 `keystore/lhasa26.jks` → Raw → 保存，
再用任意 base64 工具转换。

## 本地构建

```sh
export LHASA_KEYSTORE=/绝对路径/lhasa26.jks
export LHASA_STORE_PASSWORD=…
export LHASA_KEY_ALIAS=lhasa26
export LHASA_KEY_PASSWORD=…
./gradlew :app:assembleRelease
```

不带这些变量就是未签名的 release APK（能跑，但不能覆盖安装已签名的旧版）。

## 还没做的（可选）

jks 仍存在于 git 历史里。私有仓库、只有本人访问的前提下可以接受；
若要彻底清除，需要 `git filter-repo` 重写历史并强推，代价是所有克隆失效——目前不做。
