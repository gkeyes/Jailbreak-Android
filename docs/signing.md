# 签名

## 一句话

签名就是 App 的身份：**同一把钥匙 → 能覆盖安装；换钥匙 → 必须卸载重装**。
所以本项目只维护一把钥匙，不搞轮换、不搞多套 Secret。

## 现状

| 东西 | 在哪 |
|---|---|
| 钥匙（`lhasa26.jks`，alias `lhasa26`） | git 历史里（工作树已移出，用时恢复） |
| 口令 / alias | `keystore/keystore.properties`（随仓库走） |
| 构建取值顺序 | 环境变量 → `keystore.properties` → 不签名 |

CI（`build.yml`）在构建前用 `git show <提交>:keystore/lhasa26.jks` 把它恢复出来再签名；
本地构建把它放回 `keystore/lhasa26.jks` 就行。

环境变量（`LHASA_KEYSTORE` / `LHASA_STORE_PASSWORD` / `LHASA_KEY_ALIAS` /
`LHASA_KEY_PASSWORD`）优先级更高，是为了以后若要把口令挪去 Secrets 时**不用改代码**。

## 这么做的代价（明确写下来）

能读这个仓库的人，就能用它签出**可以覆盖安装到你手机上**的包。
前提是私有仓库、只有本人访问——在这个前提下，把钥匙放一处、口令放一处，
比在 CI/Secrets/本地三处维护同一份东西更不容易出错。

一旦仓库要公开、或者要多个人协作：
1. 把 `keystore.properties` 的四个值搬到 Actions Secrets；
2. 删掉 `keystore.properties`；
3. 代码不用改动——环境变量会优先命中。

## 恢复钥匙的命令

```sh
# 在任意有 git 的机器上
git clone git@github.com:gkeyes/Lhasa26-Android.git
cd Lhasa26-Android
git show 535ee09ab2aa2c9bd8cc6e76b2159f6c4e1cef4e:keystore/lhasa26.jks > keystore/lhasa26.jks
```

手机上也可以在网页打开那次提交的 `keystore/lhasa26.jks` → Raw 下载。

## 校验签名是否还是原来那把

```sh
apksigner verify --print-certs app-release.apk | grep 'SHA-256'
```

和手机上已装版本的签名摘要一致，就说明能覆盖安装。

## 已知未做

· `lhasa26.jks` 仍在 git 历史里。私有仓库可以接受；要彻底清除需 `git filter-repo`
重写历史并强推，代价是所有克隆失效，目前不做。
