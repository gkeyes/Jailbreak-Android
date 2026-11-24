# CVE-2026-99491 适配经验记录（lhasa / 2608BPX34C）

> 2026-11-24 实测总结。目标：在小米 18 Fold 上用 CVE-2026-99491 装载 KernelSU 模块。
> 结果：**装载成功（2 次），但无法稳定**；根因与后续正确路径见下文。

## 1. 结论摘要

| 项 | 结果 |
|---|---|
| KASLR（slide）泄漏 | ✅ 可用，多个 boot 与独立测量一致 |
| 写原语 | ✅ `spray=4096 / spread=50` 命中率 4/4；单次写不逃逸 |
| cred 改写 | ✅ `uid=0`、`CapEff=0x0e00050000` |
| KO 导入符号表 | ✅ 225 个全部从 kallsyms 取到链接期地址 |
| `finit_module` | ✅ 成功 2 次（模块 Live、`su` 可用、`/data/adb` 建立） |
| 稳定性 | ❌ 每次开 permissive 后 1–5 分钟内必然重启 |

**根因一句话**：开 permissive 只能靠写 `selinux_state` 内存；写它会清掉 `initialized` 与 `policycap`，而本机布局未知、写原语只有两种固定词，无法精确恢复。

## 2. 三种利用模式的取舍（最重要的一条经验）

上游存在三种模式，稳定性差异很大：

| 模式 | 链路 | 稳定性 | 关键防护 |
|---|---|---|---|
| **real_cred（主线）** | anchor 读（CVE-2026-98499）→ oracle 验证 pad 回收 → uinput 承载伪造链 → 借用 `init_cred` 伪造 cred → 修复 `real_cred` → `setcon` 切域 → 内联装载 | **最好** | **oracle 验证回收**、PARKED 停手、不关 SELinux |
| tracefs | kmem tracepoint 泄漏子进程 cred → 直接写 uid/gid/caps/SELinux 状态 | 中 | 无 oracle，盲写 |
| no-tracefs | 仅换 `task->cred`，fork/exec 交付 | 中低 | 首次 bootstrap 盲回收 |

**本次我们采用的是 tracefs 路线**（因为先读到的是该模式的移植仓库），因此：

- 每次都要关 SELinux → 必然破坏状态 → 必然重启
- 没有任何"动手前确认"的机制 → 写逃逸概率随时间累积

**教训：新设备适配应优先移植 `real_cred`，核心是它的 oracle 逻辑，而不是先把 tracefs 链跑通。**

## 3. 本机实测数据（可直接复用）

### 3.1 链接期地址

| 符号 | 值 |
|---|---|
| `uhid_device_add_worker` | `0xffffffc080f79ff4` |
| `selinux_state` | `0xffffffc082959630` |
| `sysctl_bootid` | `0xffffffc08296ccb0` |

### 3.2 tracefs 分配站点

| 项 | 值 | 判据 |
|---|---|---|
| cred 分配 call_site low21 | `0x6d1b4` | `etype=0x13a`、`name=cred`、`req=0xb8` |
| lsm blob 站点 | `0x35f34` | `site_probe --pair`，`req=0x28` |

注意：由 `prepare_creds+0x2c` 推导的 `0x6c02c` 是**错的**，必须以 kmem 记录里的实际 call_site 为准。

### 3.3 写原语参数

| 参数 | 结果 |
|---|---|
| `spray=1024, spread=0`（上游默认） | 全 miss |
| `spray=4096, spread=50` | 4/4 命中 |

根因：`uaf_write_once()` 用的是无间隔 `spray_fire()`；同文件的 `spray_spread()` 才带分批与 sleep。适配时必须改用它。

### 3.4 KO 符号表

```sh
# root 下（需先 kptr_restrict=0，本机厂商内核不认 CAP_SYSLOG）
su -c 'echo 0 > /proc/sys/kernel/kptr_restrict'
su -c 'cat /proc/kallsyms' > /sdcard/kallsyms.txt
su -c 'echo 2 > /proc/sys/kernel/kptr_restrict'

node tools/gen_ksu_syms.js --kallsyms kallsyms.txt \
    --undef kosyms_undef.txt --slide 0x<slide> --out ksu_syms.h
```

结果：225/225 命中，缺失 0。运行时由 loader 做 `st_value = 链接期地址 + slide`、`st_shndx = SHN_ABS`。

## 4. 失败根因（六条，均有原始证据）

1. **合法 `setenforce` 在 Enforcing 下被拒**（`rc=-1`）——所以开窗只能写内存。
2. **写 `selinux_state+0` 必然清掉 `initialized` 与 `policycap[0..5]`**，写原语无法拼出恢复值。
3. **多字段连写会放大写逃逸**：未开窗的对照实验里 `enforce` 自己变成 Permissive（某次写打偏）。
4. **重载策略从未在窗口内真正执行成功**（要么窗口没开、要么日志读不到、要么进程早退）。
5. **取证能力缺失**：无 pstore/kcore/last_kmsg；kprobe 的 `@symbol`、`@字面地址` 只读回寄存器值。
6. **`selinux_state` 在 `.bss`**：boot.img 里读不到初始字节（已验证：镜像覆盖到 `0xffffffc0828f3a00`，而该符号在 `0xffffffc082959630`）。

## 5. 设备级反直觉事实

| 事实 | 说明 |
|---|---|
| `kptr_restrict=2` 不认 `CAP_SYSLOG` | 即使 root（`context=kernel`）读 kallsyms 也全是 0，必须临时置 0 |
| `mksh` 会降权 | `/system/bin/sh` 在 `euid != uid` 时 `setuid(getuid())`；要保留 euid 必须直接 exec 静态二进制 |
| permissive ≠ 授予能力 | `cap_capable()` 独立于 SELinux，permissive 只放行 AVC |
| kprobe 不能读任意内存 | `@symbol`、`+0(@0x…)` 都只读回寄存器值 |
| `/sys/fs/selinux/enforce` 写入需策略放行 | uid=0 + `CAP_MAC_ADMIN` 在 Enforcing 下仍 `rc=-1`；只有 permissive 时才能写 |
| 写原语目标来自残留对象 `+0x5f0` | 槽位没被 spray 占住时，写入会落到任意内核地址 |

## 6. 若要继续，正确的执行顺序

1. **先移植 `real_cred` 的 oracle**：只验证"能否确定性占住槽位"，不写任何东西。
2. **修好取证链路**：loader 日志独立文件 + `chmod 0666` + 每步 `fsync`；进程名与路径固定。
3. **单动作实验**：一次运行只做一个特权动作，观察 5 分钟。
4. **再谈装载**：`real_cred` 走 `setcon`，不需要关 SELinux，因此不会有"必然重启"。

## 7. 未完成项

- `selinux_state` 真实布局（需反汇编内核或拿到带 DWARF/BTF 的 vmlinux）
- `task_struct->cred / real_cred` 偏移（可从运行时 BTF 取，尚未提取）
- oracle 逻辑移植
- 目标 shell 域的 sid（从策略中查）

## 8. 参考

- `Yunnijian/CVE-2026-99491` — 6.18 移植（tracefs 风格，本次主要参考）
- `woshigenm/CVE-2026-99491-FANXIAOCHAO` — 三模式实现，含 oracle 与 PARKED（**推荐优先参考**）
- `woshigenm/CVE-2026-99491` — 5.15 实现，AVC 缓存改写（permissive 窗口只覆盖一次 `finit_module`）
- 完整时间线（含原始输出）：`/sdcard/Download/l26-cve99491-timeline-20261124.md`
