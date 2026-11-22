# assets 台账（唯一事实来源：`tools/assets-ledger.json`）

这里放的是**会被打进 APK** 的原生程序与数据。任何新增/替换都必须同步台账，
否则 `tools/check_assets.py --strict`（CI 第一步）会直接失败。

| 文件 | 大小 | 来源 | 是否有源码 | 状态 |
|---|---|---|---|---|
| `ksud` | 4,990,848 | 上游 KernelSU，**未对接到任何 Release** | 上游开源 | 换成 `tools/ksud.lock.properties` 锁定的 v3.3.1 官方产物 |
| `uaf_plant_replay` | 88,488 | 预编译 | **无**（`plant/` 里没有对应 .c） | 黑盒，需补源码或明确标注不可重建 |
| `reach_probe` | 51,368 | 预编译 | 草稿 `plant/reach_probe.c` | 草稿未接入构建 |
| `slide_probe` | 44,776 | 预编译 | 草稿 `plant/slide_probe.c` | 草稿未接入构建 |
| `perf_slide` | 31,840 | 预编译 | 草稿 `plant/perf_slide.c` | 草稿未接入构建 |
| `pc98260-su` | 28,416 | 预编译 | 草稿 `plant/pc98260-su.c` | 草稿未接入构建 |
| `lhasa_profile.txt` | 2,046 | 仓库内数据 | 不适用 | 保持 |

被 `AssetDeployer.RUNTIME_ASSETS` 预置的是后 6 项；`ksud` 不在预置清单里，
KernelSU 接管阶段才按需投放。

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
