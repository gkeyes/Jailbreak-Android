# assets 台账（唯一事实来源：`tools/assets-ledger.json`）

这里放的是**会被打进 APK** 的原生程序与数据。任何新增/替换都必须同步台账，
否则 `tools/check_assets.py --strict`（CI 第一步）会直接失败。

| 文件 | 大小 | 来源 | 状态 |
|---|---|---|---|
| `ksud` | 4,990,848 | upstream-prebuilt | pinned |
| `uaf_plant_replay` | 99,048 | upstream-source | upstream-built |
| `reach_probe` | 45,664 | rebuilt-from-source | rebuilt |
| `slide_probe` | 43,448 | upstream-source | upstream-built |
| `pc98260-su` | 25,512 | upstream-source | upstream-built |
| `lhasa_profile.txt` | 2,046 | in-repo-data | data |
| `lhasa_99491_profile.json` | 3,440 | device-calibrated | verified |
| `cve99491_exp` | 800,696 | repo-build | pinned |
| `kernelsu-android17-6.18.ko` | 375,328 | upstream-prebuilt | pinned |

被 `AssetDeployer` / `AssetIntegrity` 使用的资产：98260 路径为 `uaf_plant_replay/slide_probe/reach_probe/pc98260-su`；99491 路径为 `cve99491_exp/lhasa_99491_profile.json/kernelsu-android17-6.18.ko`；`ksud` 两条路径共用、按需投放。

## 核对

```sh
tools/check_assets.py            # 打印核对表
tools/check_assets.py --strict   # 未登记文件也算失败（CI 用这个）
tools/check_assets.py --update   # 把算出的 sha256 写回台账
```

## ksud 怎么来

不要手工丢一个二进制进来。按锁文件拉取校验：

```sh
tools/fetch_ksud.sh              # → app/src/main/assets/ksud，校验 size + sha256
tools/fetch_ksud.sh /tmp/ksud    # 落到别处
```

升级上游版本 = 改 `tools/ksud.lock.properties` 的 `tag`/`url`/`size`/`sha256`
四个字段，再跑一次 `fetch_ksud.sh` 复核。
