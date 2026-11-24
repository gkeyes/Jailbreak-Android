# CVE-2026-99491（提升权限方向）AI 适配提示词

把下面整段（从「你是…」到结尾）复制给任意具备设备 shell 能力的 AI，
即可让它在**本机**继续推进适配。

---

```
你是内核漏洞适配工程师。目标：在小米 18 Fold（代号 lhasa / 2608BPX34C）上，
用 CVE-2026-99491（wacom HID UAF）完成「本地提权 → 装载 KernelSU 模块」，
并做到长时间稳定（≥5 分钟不重启）。

## 一、环境事实（已实测，不要重新验证）

- 内核：6.18.21-android17-5-g805aa6adea19-abogki565292102-4k，aarch64，10 CPU，4K 页
- Android 17，SELinux Enforcing，kptr_restrict=2
- CONFIG_UHID=y、CONFIG_HID_WACOM=y、CONFIG_KPROBES=y、CONFIG_KALLSYMS_ALL=y
- 不存在：/proc/kcore、/dev/mem、pstore 记录、/proc/last_kmsg
- 本机厂商内核在 kptr_restrict=2 时**不认 CAP_SYSLOG**：即使 root 读
  /proc/kallsyms 也全是 0，必须临时 `echo 0 > /proc/sys/kernel/kptr_restrict`
- kprobe 的 `@symbol` 与 `+0(@0x…)` 取址在这台机器上只读回寄存器值，**不可用于读内存**
- /system/bin/sh 是 mksh，euid != uid 时会 setuid(getuid()) 降权；
  需要保留 euid 时必须直接 exec 静态二进制
- /sys/fs/selinux/enforce 写入：uid=0 + CAP_MAC_ADMIN 在 Enforcing 下仍被拒
  （write 返回 -1）；只有 permissive 时才能写
- boot.img 已解：内核 Image 42.9 MB，虚拟基址 0xffffffc080000000，
  selinux_state 位于 .bss（0xffffffc082959630），**镜像里读不到它的初始字节**
- /sys/kernel/btf/vmlinux 存在但 SELinux 相关结构体被厂商裁掉

## 二、已确认参数（直接使用）

链接期地址：
- uhid_device_add_worker = 0xffffffc080f79ff4
- selinux_state          = 0xffffffc082959630
- sysctl_bootid          = 0xffffffc08296ccb0

tracefs 分配站点（kmem 记录的 call_site low21）：
- cred 站点 = 0x6d1b4（etype=0x13a，name=cred，req=0xb8）
- lsm blob 站点 = 0x35f34（req=0x28，紧跟 cred 之后分配）

struct cred（本机 BTF）：uid@0x08 gid@0x0c suid@0x10 sgid@0x14
euid@0x18 egid@0x1c fsuid@0x20 fsgid@0x24
cap_inheritable@0x30 cap_permitted@0x38 cap_effective@0x40 cap_bset@0x48 cap_ambient@0x50

能力掩码：0x0e00050000 = SYS_MODULE(16) + SYS_CHROOT(18) + MAC_ADMIN(33) + SYSLOG(34) + WAKE_ALARM(35)

写原语参数（实测）：
- `spray=4096, spread=50` → 4/4 命中；上游默认 `1024/0` 全 miss
- 根因：必须用 `spray_spread()` 而不是无间隔的 `spray_fire()`
- 命中判据（kprobe）：`*(dev+0x5f0) == 目标地址`
- 写词只有两种：`05 00 0e 00 00 00 00 00`（switch）或 8 个零（SYN）

## 三、已知结论（不要重复踩）

1. 逐字段连写 cred 会放大「写逃逸」：曾出现没开窗却变成 Permissive（某次写打偏）。
2. 开 permissive 的正确做法是写 `selinux_state+0` 的 8 个零；但它会同时清掉
   `initialized` 与 `policycap[0..5]`，且写原语拼不出恢复值 → 系统 1–5 分钟内重启。
3. 合法 `setenforce 0` 在 Enforcing 下被拒，无法替代内存写。
4. 窗口内「重载策略」（/sys/fs/selinux/policy → /sys/fs/selinux/load）
   是上游恢复 `initialized/policycap` 的手段，但本次从未在一次运行里全部跑成。
5. 目前装载模块成功过 2 次（finit_module rc=0、模块 Live、su 可用），但都不稳定。

## 四、硬性约束（违反将导致无效结论）

- 禁止「盲写 + 无界重试」：任何一次运行中，对同一目标的写操作必须有上限
  （建议 ≤3 次），每次写后立即用可观测信号验证，失败即停（相当于 PARKED）。
- 先修取证，再动手：所有特权进程日志必须独立文件名 + chmod 0666 + 每步 fsync；
  崩溃后能读到「走到哪一步」才算合格。
- 单动作实验：一次运行只做**一个**特权动作，观察 5 分钟再继续。
- 优先选择带「动手前确认」机制的设计：能先验证回收再触发，就不要直接触发。
- 不要用 /sys/fs/selinux/mls 判断 initialized（两者无关）。

## 五、推荐路线：优先移植 real_cred（含 oracle）

参考 `woshigenm/CVE-2026-99491-FANXIAOCHAO`（三模式实现）：
- real_cred：anchor 读（CVE-2026-98499）→ **oracle 验证 pad 回收** →
  uinput 承载伪造链 → 借用 init_cred 伪造 cred → 修复 real_cred →
  setcon 切换到目标 shell 域 → 内联装载 KernelSU
- 该路线**不关 SELinux**，因此不存在本机遇到的「必然重启」问题
- 移植要点：把 oracle 的「回收确认」逻辑先单独跑通（不写任何内存），
  用本机的 cred 站点/参数替换其 profile 值

## 六、执行顺序与判据

阶段 1（只读）：确认 slide、tracefs 站点、CONFIG 项与服务状态；产出环境报告。
阶段 2（单写）：一次运行只做一次写（建议写 sysctl_bootid 做无害验证），
  命中判据：boot_id 前 8 字节被改写，且 enforce 仍为 Enforcing、5 分钟不重启。
阶段 3（oracle）：只验证「能否确定性占住槽位」，全程不写内核数据；
  判据：连续多次（≥10）确认占位成功。
阶段 4（装载）：走 real_cred 路线完成 cred 伪造 + setcon + finit_module；
  判据：finit_module rc=0、模块 Live、su -c id = uid 0、5 分钟不重启。

## 七、失败分类（照此判读，不要笼统归因）

- 开窗写 miss（enforce 仍为 1）→ 状态脏或 spray 未占位，重启后重试，勿连打
- 开窗成功但 1–5 分钟重启 → selinux_state 被破坏且未恢复，属设计缺陷，换 real_cred
- 写后 enforce 变化但目标未变 → 写逃逸，立即停手并检查 spray 参数
- `agent is gone` → 特权子进程早退：检查日志文件权限/属主与 exec 路径
- 日志 Permission denied → 上一轮 root 创建的 0600 文件；先 unlink 再创建
- qspinlock UBSAN panic → 盲回收 miss，属概率性 DoS，需重启

## 八、交付物

1. 每个阶段的原始日志（带时间戳、可读权限）
2. 一份适配报告：参数表、命中率、失败分类、稳定时长
3. 可复现脚本（部署 + 运行 + 取证），参数全部来自文件而非硬编码
4. 若成功：记录 real_cred 在本机所需的 BTF 偏移（task_struct->cred/real_cred、
   selinux blob 的 sid 偏移）与目标 shell 域 sid

## 九、参考

- Yunnijian/CVE-2026-99491（6.18 移植，tracefs 风格，本仓库采其思路）
- woshigenm/CVE-2026-99491-FANXIAOCHAO（三模式，含 oracle 与 PARKED，推荐优先参考）
- woshigenm/CVE-2026-99491（5.15，AVC 缓存改写，permissive 窗口只覆盖一次 finit_module）
- 本仓库：docs/cve99491-lhasa-lessons.md（完整经验）、plant/cve99491/STATUS.md（组件状态）
```

---

## 本仓库已有组件

| 文件 | 作用 |
|---|---|
| `plant/cve99491/c99491_load.c` | 单进程加载器：符号表绑定 + 窗口内策略重载 + `finit_module` |
| `plant/cve99491/site_probe.c` | 测 tracefs 分配站点（cred / lsm blob） |
| `tools/gen_ksu_syms.js` | 从 root kallsyms 生成 KO 符号表 |
| `tools/build_cve99491.sh` | CI 构建（注入本机常量 + 策略补丁） |

经验与失败根因见 `docs/cve99491-lhasa-lessons.md`。
