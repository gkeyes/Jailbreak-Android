> ⚠️ **历史文档（仅存档）**：本文件是从会话日志恢复的旧 `README.md`/`exp.c` 内容，
> 描述的是 Yunnijian fake-handle/outq 老链；实现已被 `plant/99491/exp_direct.c` 的
> direct 固定词引擎取代。最终可用流程见 `docs/99491-solution.md` 与
> `plant/99491/README_direct.md`，**不要按本文档操作**。

# plant/99491 — CVE-2026-99491 `real_cred` 链（lhasa 移植）

> 本目录是 [计划 `docs/99491-test-plan.md`](../../docs/99491-test-plan.md) §4 的 T1 交付：
> 独立静态 ELF 的第二条提权链（D1/D2/D7），只保留 `real_cred` 模式可用。
> 编译产物（`build/99491/exp`）与 base64 分发由 CI/`plant.yml` 另行接入（T3 范围）。

---

## 1. 来源与许可

| 项 | 值 |
|---|---|
| 上游主线 | [`Yunnijian/CVE-2026-99491`](https://github.com/Yunnijian/CVE-2026-99491) @ `1923ac893d582e4b87b748ea033be4a004d894b1` |
| 移植基座 | `tools/realcred/exp.c`（git blob `9c58379f3dd475bfef7df20f2a4529ffe13b97cf`，226,592 B）及其 `tools/realcred/{profile.h,parked.h,README.md,build.sh}` |
| 三模式/oracle/PARKED 设计参考 | [`woshigenm/CVE-2026-99491-FANXIAOCHAO`](https://github.com/woshigenm/CVE-2026-99491-FANXIAOCHAO) @ `a5d970935dac14b7c8b0aff865322c656c8d550e` |
| 许可 | **GPL-2.0-only**；上游 `LICENSE` 与 `NOTICE` 原样保留（`LICENSE`/`NOTICE`），本移植的修改同样以 GPL-2.0-only 发布 |
| 目标设备/内核 | lhasa 2608BPX34C / `6.18.21-android17-5-g805aa6adea19-abogki565292102-4k`，4 KiB 页，SELinux Enforcing |

移植时**保留上游全部版权头**；本目录 `NOTICE` 在原文之后追加了本移植的来源与改动清单。
`exp.c` 头部有 `lhasa port` 说明块；`parked.h` 未改一字。

---

## 2. 文件

| 文件 | 说明 | 是否生成 |
|---|---|---|
| `exp.c` | 主链：anchor/OOB 泄漏 → UAF 回收（oracle 验证）→ uinput 载体 → `init_cred` 伪造 → `setcon` → ksud late-load；本移植加了分阶段 CLI 与标记契约 | 手写（上游 + patch） |
| `profile.h` | 全部 build-specific 常量的 C 形态（struct + 内置 profile + PackageManager 兜底） | **生成**：`tools/99491/gen_profile.py --gen`，禁止手改 |
| `parked.h` | `PARKED`/`RAN` boot_id 标记（同 boot 二次触发会 panic，必须拒绝） | 上游原文 |
| `build.sh` | 校验/生成 profile.h 后交叉编译（优先 zig musl，本机回退 aarch64-linux-gnu-gcc） | 手写 |
| `example-profile.json` | schema 占位样例（`verified:0`、release 不在参考表、地址为假值）；只用于工具自检，**不可上机** | 手写 |
| `LICENSE` / `NOTICE` | GPL-2.0-only 全文 / 来源与改动声明 | 上游 + 追加 |
| `README.md` | 本文件 | 手写 |

真实标定值只有一处：**`app/src/main/assets/lhasa_99491_profile.json`**（App 资产，Lead 标定）。
本目录 `profile.h` 只是它经 `gen_profile.py` 的生成物；`example-profile.json` 里的值全部是占位。

---

## 3. 构建

```sh
# 仓库根目录；Python >= 3.8，无第三方依赖
python3 tools/99491/gen_profile.py --check \
    --json app/src/main/assets/lhasa_99491_profile.json      # 只校验，0 FAIL 才继续

python3 tools/99491/gen_profile.py --gen                      # 校验后生成 plant/99491/profile.h
bash plant/99491/build.sh --self-test                        # = gen + 编译 + 主机自检
bash plant/99491/build.sh                                    # = gen + 编译
bash plant/99491/build.sh --check                            # 只校验 profile
bash plant/99491/build.sh --json plant/99491/example-profile.json   # 占位自检（会加 --allow-unknown-release）
```

- `build.sh` 每次先用 `gen_profile.py --check --gen` 重新生成 `profile.h`，**校验不过就不编译**。
- 编译器顺序：`zig cc -target aarch64-linux-musl`（CI）→ `aarch64-linux-gnu-gcc`（本机 proot，
  已验证产物 800,696 B）。输出 `build/99491/exp`，打印大小与 sha256。
- `--self-test` 只在 aarch64 主机上执行产物：`exp --self-test` 打印
  `release/kmi/backend/ksud` 并做结构自检，末尾必须出现 `SELF_TEST_OK`；`--help` 也跑一遍。
- CI（`plant.yml`）用 zig 0.13 交叉到 musl；发布前还需 `docs/99491-test-plan.md` §9 的资产台账步骤（T3）。

---

## 4. 运行与分阶段 CLI

```sh
# 二进制 + profile + workdir 由 App/调试脚本投放；设备上：
./exp --stage=leak     --profile /data/local/tmp/cve99491/profile.json --workdir /data/local/tmp/cve99491
./exp --stage=oracle   --no-ksu
./exp --stage=write    --no-ksu
./exp --stage=selinux  --no-ksu
./exp --stage=trigger  --no-ksu     # 触发可达性探针（会 PARKED，一次重启一测）
./exp                  # 等价 --stage=full
```

| 参数 | 含义 |
|---|---|
| `--stage=leak\|oracle\|write\|selinux\|trigger\|full` | 阶段闸门，默认 `full`；`CVE99491_STAGE` 同义 |
| `--profile PATH` | 运行时 JSON profile；不传则看 `$CVE99491_PROFILE` → `$workdir/profile.json` → 编译内置 profile（见 §6 fail-closed） |
| `--workdir PATH` | 工作目录（日志、`PARKED`/`RAN` 标记），默认取 profile 的 `ksu_workdir` |
| `--no-ksu` | 不走 ksud late-load；`full` 在 uid-0 shell 结束 |
| `--ksud PATH` | 强指定 ksud 加载器（等价 `CVE99491_KSU_LIB`） |
| `--spray N` / `--spread N MS` / `--cpu N` | 回收几何覆盖（默认取 profile） |
| `--force-fire` | 只绕过「本 boot 已 fire 过」的软检查；**`PARKED` boot 永远拒绝** |
| `--manager PKG` | KernelSU 管理器包名/短名（`finasu\|next\|bakasu\|sukisu\|yukisu\|sukisu_nova`） |
| `--pm-backend=auto\|pm\|binder` | PackageManager 探测方式（默认 auto，不会隐式用 binder） |
| `--self-test` | 不碰内核：加载 profile、结构自检、打印 `SELF_TEST_OK` |
| `--version` | 打印编译进去的 release 与 profile sha256 |

### 阶段语义（与计划 §4/§8 一一对应）

| stage | 做什么 | 明确不做 | 成功标志 / 退出码 | 遗留状态 |
|---|---|---|---|---|
| `leak` | profile release/page_size 校验；anchor OOB 读 `worker.func` 求 slide，校验 2 MiB 对齐与 `.text` 区间 | 不触发 UAF、不写 `PARKED`、不占本 boot 的 fire 额度 | `[p] profile_ok` + `[p] anchor slide=0x…` + `[+] leak stage complete`，0 | 无（进程正常退出） |
| `oracle` | UAF 触发 + 只做**回收验证**（kmem oracle 命中 touch 槽位）；命中后立刻停 | 不做任何内核写（连 self-cell 都不做）；oracle 不可用就拒绝盲触发 | `[+] oracle hit: …` + `[+] oracle-only stop …` + `[+] oracle stage complete (no kernel write)`，0 | 已触发 UAF → 留 armed holder 并 `PARKED`；本 boot 不再触发 |
| `write` | bootstrap + 身份校验（`comm` 标记）后**单次 8 字节**写自身 cred 的 `cap_effective`（值 `0x16`，仅 DAC caps），`capget` 回读校验；uid/euid 必须仍为 2000 | 不换 cred、不碰 SELinux、不装模块；uid/euid/fsuid 不动 | `[+] write cap_effective=0x16 uid=2000 euid=2000 uid_unchanged=1`，0 | armed holder 保留 → `PARKED` |
| `selinux` | 通过链把 `selinux_state` 的 `{enforcing,initialized}` 清零（permissive 窗口，selinuxfs 复核 `enforce=0`），随后写回 `0x101`（enforcing=1/initialized=1）并用 selinuxfs 复核 `enforce=1`，再 disarm outq | 不载模块、不 `setcon` | `[+] selinux_window restored=1 enforce=1`，0 | armed holder 保留 → `PARKED` |
| `trigger` | **触发可达性探针（当前排障用）**：UAF + oracle 回收后，把回收的 fake `input_dev` 做成 direct-vals 垫片（`grab=0`、`num_vals=0`、`max_vals` 大、`vals = selinux_state-1`），只发**一次** pad MUTE 报告：EV_SW 固定词 `{05 00 0e 00 …}` 落在 `selinux_state-1`，于是 `enforcing(+0)=0x00`；对比前后 `getenforce`。`CVE99491_TRIGGER_MODE=chain` 时改用 fake-handle 链写同一个词（隔离 direct-vals 与 chain 两条路径） | 不载模块、不 setcon、不碰 cred/outq；只写这一个固定词；不恢复策略（重启恢复） | `[step] trigger probe: mode=direct|chain …` + `[dbg] trigger probe: … enforce before=1 after=0` + `TRIGGER_PROBE_OK`，0；未变则 `TRIGGER_PROBE_FAIL`，1（均 PARKED） | 已触发 UAF → armed holder + `PARKED`，必须重启 |
| `full` | 完整 real_cred 链：伪造 cred → swap → `cred == real_cred` → `setcon` → outq disarm → 交给 profile 选定的 ksud late-load → `MODULE_LOADED` → 模块 Live 校验 → 厂商策略（可关）→ `Enforcing` 恢复 → `su -c id` 验收 | — | 见 §5 标记契约，0 | 模块 Live，`su` 为 `u:r:ksu:s0`；临时 root，重启消失 |

失败语义（计划 D4）：**写内核之前**的失败（leak/oracle 阶段、profile 错）可安全返回、允许回退 98260；
**写内核之后**的任何失败都 `PARKED`（armed holder 保持描述符、本 boot 拒绝再跑）→ App 必须提示重启，
不得自动回退另一条链（dirty boot 两链共享）。

---

## 5. 机器可解析标记契约（App 解析，逐字稳定）

每行独立、行首前缀固定；**除下列 `PARKED` 外全部输出到 stdout**（`PLOG` 细节写 workdir 下的 `exp2.log`）。

| 标记（逐字前缀） | 出现时机 | 含义 |
|---|---|---|
| `[p] profile_ok release=<uname -r>` | profile 加载且运行时 release/page_size/arch 全部精确匹配之后（任何阶段、任何 kernel 访问之前） | 标定表与当前 build 100% 对应；不匹配时不会出现，而是 `PROFILE_MISMATCH …` + 退出码 3 |
| `[p] anchor slide=0x<hex>` | KASLR anchor 泄漏成功、`slide % kaslr_align == 0` 且 `worker.func ∈ [stext,etext)` 之后 | 运行时−链接期位移；后续所有 target 的基础 |
| `[+] swap uid=0` | `task->cred` 换成伪造 cred 且 `getuid()/getgid()` 已为 0 之后（full） | 提权第一步落地 |
| `[+] cred == real_cred` | `real_cred` 被补成同一伪造指针、`capget` 看到 full caps 之后（full） | 后续 `setcon`/内核调用不会再被 `real_cred` 拽回 |
| `[+] setcon` | `/proc/self/attr/current` 写入 profile 的 `selinux_shell_domain`（`u:r:shell:s0`）并回读确认之后（full） | 域转换完成 |
| `MODULE_LOADED` | `/proc/modules` 出现 `kernelsu … Live`（full，late-load 阶段） | 模块已 Live |
| `[f] module_live=1 enforce=1` | 模块 Live 且 `/sys/fs/selinux/enforce` 复核为 1（full 收尾） | 最终成功标记之一 |
| `[f] su_check=uid=0 … u:r=ksu:s0` | `su -c id` 输出同时含 `uid=0` 与 `u:r=ksu:s0`（full 收尾） | 最终验收：`su` 真的可用且落在 ksu 域 |
| `PARKED` | 任何「已 arm 后失败/主动停车」的路径（含 oracle/write/selinux 阶段结束）：先打印失败原因行，再单独一行 `PARKED` | 本 boot 内核状态不可信，**必须重启**；App 不得重试、不得切 98260 |
| `PROFILE_MISMATCH <细节>` | profile 校验/运行时不匹配、或运行时 JSON 与编译内置 profile 不一致 | 配置错误（退出码 3），不执行任何危险动作 |

辅助行（同样稳定，App 可选用）：`[p] profile_source=…`、`[p] stage=<stage> mode=real_cred`、
`[+] oracle hit: target slot reclaimed by our skb (depth N)`、`[+] oracle-only stop …`、
`[+] write cap_effective=…`、`[+] selinux_window restored=1 enforce=…`、`[+] TOTAL_SECONDS=…`、
`[f] su_check=FAILED`、`[-] <原因>`（失败原因）；
`trigger` 阶段另有：`[step] trigger probe: mode=direct|chain …`、`[dbg] trigger probe: mode=… enforce before=… after=…`、
`TRIGGER_PROBE_OK` / `TRIGGER_PROBE_FAIL`（`CVE99491_TRIGGER_MODE=chain` 走 fake-handle 链写同一固定词）。

`PANIC`：进程无法在 panic 时打印任何标记；App 侧以「设备重启 / boot_id 变化 / 无任何收尾标记」
判定 panic（计划 §5：同步骤跨开机 2 次相同崩溃即停）。

`CVE99491_CHAIN_DEBUG=1` 会额外打印只读诊断（默认关闭，不改变标记契约）：
- `[dbg] pair-up hid …` / `[dbg] pair-up evdev …`：touch/pad 两个 UHID 是否被 wacom 认领、
  HID_PHYS 是否成对、pad input 节点是否带 `SW_MUTE_DEVICE`（`mute_bit=1`）；
- `[dbg] selfcell …`：self-cell 每一步 `pc_write` 的 rc 与 chain anchor 自己的 `outq_read` rc/errno
  （`rrc=1`=EAGAIN head==tail，`-1`=EFAULT，`0`=命中）。注意：**不要**用 `leak_word()`/新建 anchor
  去“回读”链 anchor 的 0x1184/0x1188——新 anchor 读到的是它自己的字段，不是链 anchor 的内存。

### 退出码

| 码 | 含义 |
|---|---|
| 0 | 该 stage 达到目标（full = 全链成功，`su_check` 通过） |
| 1 | 链/阶段失败（含 `PARKED`；leak 受只读保护，失败也不写 PARKED） |
| 2 | 用法错误（未知参数/stage、非法的 `--spray/--cpu`、`--mode=tracefs/no-tracefs` 被拒绝） |
| 3 | profile 错误：JSON 非法/字段缺失/运行时 release、page、arch 不匹配，或运行时 JSON 与编译内置 profile 不一致（`PROFILE_MISMATCH`） |

---

## 6. profile 与 fail-closed

- 唯一事实源：`app/src/main/assets/lhasa_99491_profile.json`（字段清单与校验规则见
  [`tools/99491/README.md`](../../tools/99491/README.md)）。
- 构建期：`gen_profile.py --check --gen` → `plant/99491/profile.h`（C 常量 + `cve99491_profile_builtin()`）；
  `exp.c` 里没有任何 pyb110/lhasa 的符号地址、结构偏移或 spray 数字。
- 运行期：
  1. `--profile`/`CVE99491_PROFILE` 显式给出 → 文件必须存在且可解析（fail-closed，不回落内置）；
  2. 只给了 `--workdir`/默认 → 先试 `<workdir>/profile.json`，不存在则用**编译内置 profile**；
  3. 用显式 JSON 时，除 `label`/`verified`（以及只在构建期交叉校验用的 `stext/etext`）外，
     **每个标定值必须与编译内置 profile 完全一致**，否则 `PROFILE_MISMATCH` 退出 3。
     含义：改了 JSON 就必须重新跑 `build.sh` 再部署，App 不能把旧二进制配新 JSON 用。
  4. 运行 `uname -r` 与 profile `release` 必须**逐字相等**；`page_size`/`arch` 同样精确匹配。
- `verified:0` 当前会打印一条警告（stderr）；发布门禁由 `gen_profile.py --require-verified` 或 App 侧决定。

---

## 7. 厂商相关逻辑（OPLUS / 厂商 HAL）

上游 `tools/realcred/exp.c` **没有** ColorOS/Oplus 的 `root_check`/`oplus_secure_guard_new`/`pkl`/
`persist.sys.*` 代码分支（那些在另一条 W61821/k61821w 链里）；本移植也没有新增。本文件里与厂商相关的只有：

1. **KSU 注入策略后补厂商 HAL**——`VENDOR-SPECIFIC` 注释处（`ksu_patch_main()`）：
   `hal_patch_enable=1` 且模块 Live 后 `sys.boot_completed != 1` 时，才通过 `ksud debug su` 打
   `sepolicy patch 'permissive { <hal_patch_domains> }'`；随后恢复 `enforcing=1`。
   两个开关都在 profile：`hal_patch_enable`（当前 JSON = 0，即严格按计划 §6「仅异常时补」，关闭）与
   `hal_patch_domains`（默认 `hal_audio_default hal_camera_default`）。
2. **补丁必须由 uid-2000 进程执行**（`setresuid` 钩子/OPLUS `root_check` 的历史原因）——因此
   late-load helper 在提权前 fork；这是流程性约束，无厂商常量。
3. `ksu_backend`/`ksu_ksud_path`/`ksu_manager` 等 KSU 选择全部来自 profile（当前 `asset` +
   `/data/adb/ksud`），App/设备差异不需要改代码。

若后续 HyperOS 与 ColorOS 出现需要分支的行为，请一律用 profile 开关 + `/* OPLUS-SPECIFIC */` 注释加入，
不要删除上游逻辑。

---

## 8. 安全与操作纪律

- **一 boot 一次 fire**：首次 fire 前就写 `PARKED`；armed holder 常驻直到重启。`--force-fire` 只绕过
  RAN 标记，不绕过 `PARKED`。
- `--stage=leak` 是唯一不占 fire 额度、不写 `PARKED` 的阶段；`oracle/write/selinux/trigger` 结束后
  同样会 `PARKED`（已触发 UAF，slab 状态不可复用），计划 §5 的「失败即 PARKED、本 boot 不再写」同样适用。
- 本链真实触发 UAF；失败可能 panic/重启。禁止 `setenforce 0`、写分区、改 cmdline、卸载/替换 KSU 等
  §5 红线动作。
- 日志与 `PARKED`/`RAN` 标记都在 `--workdir`（默认 `/data/local/tmp/cve99491`）；证据按计划先 fsync 到
  `/sdcard/Download/DSH-Go/99491/<runid>/`。

---

## 9. 上游差异（本移植改动清单）

1. **CLI**：新增 `--stage=leak|oracle|write|selinux|trigger|full`（默认 full）、`--self-test`、`--version`、
   `--ksud`、`CVE99491_STAGE`；`--mode=tracefs/no-tracefs` 保留代码但 CLI 直接拒绝（D1：只保留 real_cred）。
2. **阶段闸门**：leak 在 KASLR 后、建 host anchor 前返回；oracle 复用上游 `CVE99491_ORACLE_ONLY` 钩子
   并把「回收命中」当作成功（并修掉该钩子返回 -1 的旧行为、禁止盲触发）；write/selinux 在
   `run_real_cred` 内插入一次性闸门与 holder 收尾；trigger 走独立的 `run_trigger_probe()`（见 §4/§5）。
3. **标记契约**：`[p] profile_ok`、`[p] anchor slide=`、`[+] swap uid=0`、`[+] cred == real_cred`、
   `[+] setcon`、`MODULE_LOADED`、`[f] module_live=1 enforce=1`、`[f] su_check=…`、`PARKED`、
   `PROFILE_MISMATCH`（上游只有零散 `[*]`/`[+]` 日志）。
4. **profile 管线**：`profile.h` 由 JSON 生成（含 `stext/etext`、`kaslr_align`、`ksu_backend`、
   `hal_patch_*`、`selinux_policycap` 等扩展字段）；内置 profile 回落；显式 JSON 与内置 profile 逐字段
   比对（`PROFILE_MISMATCH`）；KASLR 校验分两层——`profile_validate()` 用**链接期**符号对
   `[stext,etext)`，运行期用**平移后**的 `[stext+slide, etext+slide)` 校验 `worker.func`
   （运行时地址不能直接与链接期区间比较），且 `slide % kaslr_align == 0` 为 fail-closed。
5. **KSU 加载器**：新增 profile 驱动的 `auto|asset|manager` 选择（D3 优先现有 assets ksud），
   模块 Live 后 `MODULE_LOADED` + `Enforcing` 复核 + `su -c id` 验收。
6. **厂商 HAL 修补**：改成 profile 开关 + 条件触发（`sys.boot_completed`），不再无条件执行。
7. **诊断**：`CVE99491_CHAIN_DEBUG` 的触发源绑定诊断（`[dbg] pair-up hid …` / `[dbg] pair-up evdev …`：
   pad 是否被 wacom 驱动认领、pad input 节点是否有 `SW_MUTE_DEVICE`）+ self-cell 的 `pc_write` rc 与
   chain anchor 自身 `outq_read` rc/errno；**不**用新建 anchor 的 OOB 读回读链 anchor（会读到新设备字段，
   结论无效）。
8. **触发可达性探针**：`--stage=trigger`（5.15 风格 direct-vals 固定词写，只写 `selinux_state` 一个零词，
   用 `getenforce` before/after 判定「pad 报告是否到达回收后的 fake input_dev」）。direct-vals 只能写
   `{u16 type,u16 code,s32 value}` 固定词（例如 EV_SW/SW_MUTE 或 SYN 零词），**不能**写 p0 这种任意
   64 位值；bootstrap 的任意 8B 写仍必须用 6.18 fake-handle 链。
9. **健壮性**：profile parser 容忍 `calibration` 之类嵌套元数据；`combine_base()` 注释按 profile 修正。

---

## 10. 验证状态与待办

**已验证（2026-11-25，Lead 在 proot 本机执行）**

```text
python3 tools/99491/gen_profile.py --check --json app/src/main/assets/lhasa_99491_profile.json
→ OK（schema + 区间 + 对齐校验通过；verified=0 仅 WARN；fields=112）

bash plant/99491/build.sh --self-test → RC=0
→ [gen] 重新生成 plant/99491/profile.h
   profile.h sha256 = fd86e3bc407f3233…（来源 JSON sha256 = ecf40bb8d4490804…；两者是不同对象）
→ self-test: release=6.18.21-android17-5-g805aa6adea19-abogki565292102-4k arch=arm64
             page=4096 verified=0 kaslr_align=0x200000 fields=112
→ self-test: kmi=android17-6.18 backend=asset ksud=/data/adb/ksud
→ build/99491/exp: ELF aarch64 static stripped，800,696 B
  sha256 3623325a28366e9cfab14116cf1b449506bbbaa4f96e0757b27b4f6792021f97
```

- `profile.h` 由 `gen_profile.py` 从当前 JSON 生成（header 注释里的 `sha256` 是**JSON 的**
  sha256，不是 `profile.h` 文件本身的 sha；文件 sha 以生成时刻为准，同一 JSON 内容确定性生成）。
- **真机排障状态（2026-11-25 晚）**
  - [x] 触发源/描述符已验证（Lead 的 pair-check，clean boot）：`wacom-pair-touch Finger`、
        `wacom-pair-pad Pad/Pen` 均由 wacom 认领；pad 报告 `{02 02}` 在 touch 节点产生
        `EV_SW SW_MUTE_DEVICE=1`，`{02 03}` 产生 value=0 ⇒ `wacom_intuos_pad → input_report_switch(
        shared->touch_input)` 路径存在，**不需要换 rdesc/触发源**。
  - [ ] **卡点**：clean boot `--stage=write` 下 oracle `depth=64` 命中，但自检链从未在目标写入
        （chain anchor 的 `outq_read` 恒为 `rrc=1` EAGAIN）；已加 `--stage=trigger` 探针区分
        「pad 报告未到达回收后的 fake dev」与「fake-handle 链某一环未执行」：
        - `--stage=trigger` 默认 direct-vals：UAF 后 pad MUTE 只产生一个 EV_SW 固定词
          （`input_sync` 的 SYN 事件被 fake dev 的 evbit 挡掉，不会追加零词），把它落在
          `selinux_state-1` 让 `enforcing(+0)` 变 0，用 `getenforce` before/after 判定；
        - `CVE99491_TRIGGER_MODE=chain`：改用 fake-handle 链写同一个固定词，若 chain 也 OK 说明
          触发+链都通，bootstrap 问题的范围就缩小到 p0/outq 读写路径；
        - 若 direct OK、chain FAIL ⇒ fake-handle 环节（H/P/D 布局、handle_events 间接调用）；
          若 direct FAIL ⇒ UAF 后 pad 报告没到 `shared->touch_input`，转 5.15 路线重评。
  - [x] KASLR 校验修正（Lead）：运行期 `worker.func` 必须对 `[stext+slide, etext+slide)`；
        `stage=leak` 已全绿（`slide=0x1327e00000`）。
  - [ ] `verified` 由 Lead 在 S6/S7 通过后改 1；发布门禁用 `gen_profile.py --require-verified`。
  - [ ] T3：`plant.yml` 增加 99491 编译/publish 步骤、`tools/equiv.py` 基线、ledger 条目（本目录不负责）。
  - [ ] App（T2）：`[99491]` 通道、阶段/标记解析、`PARKED`→dirty boot 阻断、失败 fail-closed 回 98260。
