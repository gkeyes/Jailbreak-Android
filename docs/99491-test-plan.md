# 第二条提权链（CVE-2026-99491 real_cred）测试与适配计划

> 状态：已批准（2026-11-25），执行分支 `next-99491-realcred`（从 `next` @349bc20 切出）。
> 本文件是唯一的测试计划事实源；实现进度与证据见 `docs/99491-adaptation.md`。

## 0.1 路线修正（2026-11-25 23:40，真机证据驱动）

**背景**：Yunnijian/PYB110 的 `real_cred` 链在 lhasa 6.18.21 上卡在 "self cell install failed"；
同平台成功实现（[ChaYeWuu/XRING-CVE-2026-99491](https://github.com/ChaYeWuu/XRING-CVE-2026-99491)、
[ChaYeWuu/prague-CVE-2026-99491](https://github.com/ChaYeWuu/prague-CVE-2026-99491)）用的是
**5.15 式固定词直写**（`dev->vals` 直写、evbit 不含 EV_SYN、不碰 h_list/handle 间接调用、每写一次重建 UAF），
而非 fake-handle/outq 持久链。

**真机验证（clean boot c2c99590，Enforcing）**：
`--stage=trigger` 把 EV_SW 固定词落到 `selinux_state-1` → `getenforce` 1→0，`TRIGGER_PROBE_OK`。
结论：UAF 触发、回收、pad 报告到达悬垂 `touch_input`、8 字节固定词写全部成立。

**因此 S5/S6 改为**（新引擎 `CVE99491_ENGINE=direct`，保留 upstream 链代码）：
1. tracefs `kmem_cache_alloc` raw ring 抓 cred（`bytes_req=0xb8`，call-site low21 `0x6d1b4`；真机已验证 tracefs 权限：`rss_stat/trigger` 可写、`trace_pipe_raw` 可读）；
2. euid oracle：`vals=cred+0x14` 值0词 → sgid=0x000e0005 / euid=0，`geteuid()` 验证；
3. caps：`vals=cred+0x3e` 值1词 → cap_effective bit16 (CAP_SYS_MODULE)；
4. permissive：走 AVC 决策节点（`node+0x1c` flags bit0），不写 `selinux_state`；
5. endgame：uid0+CAP_SYS_MODULE+permissive 下 `ksud late-load` → `/proc/modules` 出现 `kernelsu ... Live` → 恢复 Enforcing → `su -c id` 验收。
6. 固定词写每次独立 UAF；PARKED 语义与重启预算不变；触发源仍为 wacom pad MUTE 报告。

## 0. 总原则：站在已验证的链上移植
不重写利用链。直接移植已在同版本内核 6.18.21 硬件验证的
[Yunnijian real_cred 链](https://github.com/Yunnijian/CVE-2026-99491)（clean boot 实测 1.4s；
免符号表），只重建本 build 不同的常量，每个常量双来源交叉校验后才写入 profile。
历史失败原因（黑盒链、参数靠猜）在流程上排除。

## 1. 目标与验收
**目标**：`next-99491-realcred` 上打通第二条独立提权路径：
shell(uid2000, Enforcing) → 临时 root（uid0+full caps+shell 域）→ KernelSU LKM late-load →
`su -c id` = `uid=0 … context=u:r=ksu:s0` → Enforcing 恢复；App 内与 98260 并选，98260 保留回退。

**验收**
1. S1 补丁状态门通过（静态：`wacom_remove_shared_data` 无 `synchronize_rcu`、
   `wacom_intuos_pad` 无 rcu 读锁/`wacom_report_touch_mute`；实证：98499 OOB 读可达）。
2. 本 build profile 100% 标定并通过 `tools/99491/gen_profile.py --check`。
3. S2–S7 阶段测试全绿。
4. 冷启动连续 3/3 成功，单次 ≤10s，成功后 5 分钟稳定，无 panic/重启。
5. 98260 同分支回归 2/2 成功。
6. App 一键可用；99491 失败 fail-closed；98260 可选。
7. CI 绿：单测、`assembleRelease`、签名校验、`check_assets.py --strict`。
8. `docs/99491-adaptation.md` 归档证据。

**非目标**：永久 root、解锁 BL、改分区、替换 98260、其他内核 build。

## 2. 已核实基线（2026-11-25）
| 项 | 值 |
|---|---|
| 设备/内核 | lhasa 2608BPX34C / `6.18.21-android17-5-g805aa6adea19-abogki565292102-4k` |
| 内核构建 / SPL | 2026-09-23 / 2026-10-01 |
| shell | uid 2000, `u:r:shell:s0`, Enforcing；组含 uhid(3011)、readtracefs(3012) |
| `/dev/uhid` | `crw-rw-rw-`；`wacom` 驱动在；`/dev/input/event0..9` |
| tracefs | `rss_stat/trigger`、`kmem_cache_alloc/enable` 可写；`trace_pipe_raw` 可读 |
| perf | `perf_event_paranoid=-1`；CVE-2026-98937 已修补（不用） |
| 98499 泄漏 | 已漏出内核堆指针；6.18 公式 `uhid+0x50+4*index`，`worker.func` @ +0x2408 |
| 当前 slide 缓存 | `0x10e7400000`，boot_id `674a5392-…` 与当前 boot 一致 |
| shell 权限边界 | 读不到 kallsyms/BTF；root（KSU `su`, `u:r=ksu:s0`）可用但缺 CAP_SYSLOG → 符号从 boot Image 离线还原 |
| 参考 6.18 常量 | `evbit@0x28 swbit@0xc8 sw@0x1c0 event_lock@0x1f0 num_vals@0x5e8 max_vals@0x5ec vals@0x5f0`；`sizeof(input_dev)=0x640` |

## 3. 方案决策
- **D1**：移植 real_cred 模式（oracle 验证后写、`setcon`、免符号表）；W61821（468 符号表）备选保留。
- **D2**：独立静态 ELF asset（GPL-2.0 源码 + LICENSE/NOTICE，独立进程）。
- **D3**：优先用现有 assets `ksud`（v3.3.1）`late-load --kmi android17-6.18 --allow-shell`；失败切管理器 `libksud.so`。
- **D4**：仅"零内核写前"失败可自动回退 98260；写后失败 → dirty boot，要求重启。
- **D5**：验收前 99491 opt-in；验收后默认仍 98260。
- **D6**：分支 `next-99491-realcred`；不碰 main。
- **D7**：GPL-2.0-only 源码入 `plant/99491/`。

## 4. 改动清单
1. `plant/99491/**`：移植 exp（仅 real_cred）+ parked/profile + 分阶段 CLI
   （`--stage=leak|oracle|write|selinux|full`、`--no-ksu`、`--profile`、`--workdir`）+ build.sh + LICENSE/NOTICE/README。
2. `app/src/main/assets/lhasa_99491_profile.json`（唯一事实源）；`tools/99491/gen_profile.py`（校验 + 生成 C header；fail-closed）。
3. 探针：`plant/wacom_anchor.c`（98499 只读泄漏，输出 `slide=`）；`plant/cred_site.c`（tracefs 只读测 `cred_site_low21`）。
4. App：`WorkflowEngine` RootPath/双链；`AssetDeployer`；`BootGuard` 标记；UI 路径选择；日志与导出。
5. CI/工具：`plant.yml` publish、ledger 新条目、单测。
6. 文档：本文件、`docs/99491-adaptation.md`、`plant/NOTES.md`、README。

## 5. 不随机测试纪律
1. 设备命令全部来自 `tools/devtests/99491/*.sh`，一次一个脚本执行。
2. 每阶段预写"预期输出正则 + 退出码 + 超时"；全匹配才 PASS；不匹配立即停并归类，不调参重试。
3. 运行前校验 boot_id / profile sha / dirty 标记 / slide。
4. 重试预算：anchor 3 次/开机；oracle 2 次；写阶段 1 次；全链 2 次；同步骤跨开机 2 次相同崩溃 → 停。
5. 失败即 PARKED；本 boot 不再写。
6. 证据先 fsync 到 `/sdcard/Download/DSH-Go/99491/<runid>/`。
7. 红线：`setenforce 0`、写/刷分区、解 BL、Magisk/Zygisk、卸 KSU、删 `/data/adb`、改 cmdline、未审 `.ko`。

## 6. 手机参数变更矩阵
| 项 | 现值 | 动作 | 恢复/验证 | 风险 |
|---|---|---|---|---|
| `kernel.kptr_restrict` | 2 | 标定阶段 root 临时 0 | 写回 2，双读验证 | 信息暴露窗口 |
| tracefs `tracing_on`/`rss_stat/trigger`/`trace_pipe_raw` | 关 | 沿用 slide_probe 方案 | 测完关 tracing、清 trigger | 只读 |
| `/dev/uhid` | 666 uhid 组 | 创建/销毁虚拟 HID 对 | 销毁关 fd | S5 起 UAF 风险 |
| `/dev/uinput` | 待 S1 | real_cred 载体（若存在） | 关 fd | 缺失→备选模式 |
| SELinux | Enforcing | 不 setenforce；S5c/S6 内存窗口 + 现网策略重载，成功恢复 | 每步 getenforce；失败重启 | 窗口期最高 |
| KSU 模块 | 当前 Live | 每次重启后 ksud late-load 重载 | 重启卸载 | Live 后不重载 stock policy |
| `/data/adb` | 现状 | 仅 ksud PATH 失败时临时 711 | 恢复 0700 | 需批准 |
| HAL 策略 | 默认 | 仅模块 Live 后异常时补 permissive（记 policy hash） | 重启恢复 | 音频/相机 |
| 系统属性 | 不改 | 不设未知 prop | — | — |

**不改**：boot/recovery/分区、BL、cmdline、SELinux 配置文件、Magisk、第三方 `.ko`。

## 7. 标定清单（双来源）
| 字段 | 方法 | 校验 |
|---|---|---|
| `release` | `uname -r` | 精确匹配本 build |
| `stext/etext` | `lhasa_profile.txt` + boot Image | 一致 |
| `sym_uhid_worker` | ① boot Image 符号 ② 98499 泄漏 `worker.func − slide` | 两来源相等 |
| 其余 symbols（ihe_default/inject_event/selinux_state/init_cred/per_cpu_offset/runqueues/input_dev_list） | boot Image（vmlinux-to-elf，anchor 校验） | 区间正确；`selinux_state=0xffffffc082959630` |
| BTF 偏移（task/cred/input_dev/input_handle/input_handler/uhid/per_cpu/runqueues） | root 导出 `/sys/kernel/btf/vmlinux` | `cred`=0xb8、`k_itimer`=0x180、`input_dev`=0x640；BTF×反汇编交叉 |
| `cred_site_low21`/`cred_req`/`cred_bytes` | tracefs kmem 实测 | 3 次一致 |
| KCFI 常量 | 内核镜像 `__cfi_*`/反汇编 | 与参考对照 |
| SELinux 窗口 | enforcing@0/initialized@1/policycap/restore/policy 大小 | BTF + policy 只读复核 |
| 几何 | spray 参数/页大小/在线 CPU | 实测对齐 |
| KSU | manager/ksud uapi/KMI/KO | 与 assets 一致 |
| 厂商 guard | `/proc/modules`/kevent 生产者/HAL 类型 | 与 ColorOS 差异 |
| KASLR 粒度 | 多次重启 slide | 2MB；若 512KB 改校验 |

## 8. 阶段测试（gate 制）
- **S0 基线**（只读）：环境快照、boot_id、98260 现状、slide 缓存；证据目录。G0 完整。
- **S1 补丁状态与可达性**（只读）：98499 OOB 读 → 堆指针+`worker.func`+slide；boot Image 反汇编
  `wacom_remove_shared_data`/`wacom_intuos_pad`；`/dev/uhid`、wacom、`/dev/uinput`、tracefs、KSU manager。
  **G1**：两独立证据一致 → 继续；已修补 → 终止本路线（保留 98260，属提前止损）。
- **S2 KASLR anchor**（只读）：3 次泄漏一致、2MB 对齐；反推 `sym_uhid_worker`。G2 通过。
- **S3 符号/BTF/常量**（root 只读）：`dd` boot_a + BTF 导出 → vmlinux-to-elf → profile。G3 `--check` 100%。
- **S4 cred-site**（只读）：3 次一致（low21、`bytes_req=184`、cache=cred）。G4 3/3。
- **S5 写原语分级**：
  - S5a oracle-only（有界 UAF 触发不写）：G5a 3/3 命中无 panic；否则 PARKED+重启。
  - S5b 单次 8 字节写（自身 cred fsuid/cap，uid/euid 不动）：G5b 跨重启 2 次成功、5min 稳定。
  - S5c SELinux 窗口（不载模块）：G5c 2 次成功、Enforcing 恢复、无重启。
- **S6 全链**（real_cred + ksud late-load）：标记 `[+] swap`/`cred == real_cred`/`setcon`/`MODULE_LOADED`/
  `su_check=uid=0 … u:r=ksu:s0`/`Enforcing`；单次 + 5min。G6 1 次成功。
- **S7 稳定性**：冷启动 3 次全链。G7 3/3。
- **S8 App 集成**：分支 APK 真机；99491 一键；故障注入 fail-closed 回退；dirty 阻断；98260 回归 2 次。G8 全绿。
- **S9 CI/发布**：`[apk]` 绿、artifact 签名/证书、单测、`check_assets --strict`。G9 绿。

## 9. 失败分类与备选
| 症状 | 归因 | 处理 |
|---|---|---|
| 静态判据已修补 | wacom fix 回移 | 终止路线，保留 98260；另评 98256/MM 89754 |
| `/dev/uinput` 缺失 | 载体不可用 | 切 no-tracefs 模式或 W61821 链 |
| anchor 泄漏失败 | index/绑定差异 | 核对 2284/2285 与 2286/2287；≤3 次；仍失败→终止 |
| oracle miss / PARKED | 回收未命中 | PARKED，重启；2 次同崩溃→重评估 |
| qspinlock UBSAN / cred swap panic | 概率性 DoS | 重启；2 次同崩溃→重评估 |
| SELinux 窗口恢复失败/HAL 异常 | 策略问题 | 立即重启；调窗口顺序/跳过 HAL 补 |
| 模块加载失败 | ksud/KMI/KO | 切 libksud 收尾；重启 |
| >10s 但成功 | 性能 | 记录，不阻塞 |

## 10. 契约/数据
- 新资产 + ledger（`license: GPL-2.0-only`、`sourceDraft`、`usedBy`、`status`）。
- `lhasa_99491_profile.json` schema：`format/cve/release/verified` + §7 字段；未命中 → `PROFILE_MISMATCH` 并退出。
- 引擎标记：成功/中止/重试/PARKED；`boot dirty` 两链共享。
- UI：`FoldUiState.rootPath/rootPathAvailable`、`FoldEvent.PATH_SELECT`、`root_path` 持久化。
- 日志：`[99491]`/`[98260]` 通道前缀；导出含 path/profile sha/阶段/耗时。

## 11. 分工（Agent Teams）
- **Lead**：真机 S0–S7、验收、最终 review/CI/提交。
- **T1 port/tooling**：`plant/99491/**`、`tools/99491/**`。
- **T2 app**：`app/**`、`design/**`。
- **T3 CI/docs**（Lead 兼）：`.github/**`、`tools/assets-ledger.json`、`docs/**`、README、`plant/NOTES.md`。
- 设备脚本 `tools/devtests/99491/**` 归 Lead（需真机执行）。

## 12. 时间
M0 批准 → M1 S1 判定（0.5 天）→ M2 标定（1 天）→ M3 写原语/窗口（1–1.5 天）→ M4 全链+3 冷启动（1 天）→
M5 App+CI（1 天）→ M6 用户确认合并/发布。合计 4–5 天。

## 13. 假设
- 批准只读 root 标定（`dd boot_a`、临时 `kptr_restrict=0` 恢复）；否则走厂商 OTA 离线提取（+1–2 天）。
- 接受 GPL-2.0 源码入仓库（独立进程、非链接）。
- 分支名 `next-99491-realcred`；99491 opt-in、98260 默认。
- 测试期间允许重启与短暂 SELinux 窗口风险（PARKED/证据保护）。

## 14. 进度跟踪
| 阶段 | 状态 | 证据/提交 |
|---|---|---|
| S0 基线 | 待开始 | |
| S1 补丁/可达性 | 待开始 | |
| S2 anchor | 待开始 | |
| S3 标定 | 待开始 | |
| S4 cred-site | 待开始 | |
| S5a/b/c | 待开始 | |
| S6 全链 | 待开始 | |
| S7 稳定性 | 待开始 | |
| S8 App 集成 | 待开始 | |
| S9 CI/发布 | 待开始 | |
