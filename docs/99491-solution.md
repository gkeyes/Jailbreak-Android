# CVE-2026-99491 第二条提权路径：解决方法与关键思路

> 目标设备：Xiaomi 18 Fold（`lhasa` / 2608BPX34C），kernel
> `6.18.21-android17-5-g805aa6adea19-abogki565292102-4k`，Android 17，SELinux Enforcing。
> 结论：**已真机打通** —— 从 shell(uid 2000, u:r=shell:s0) 出发，加载 KernelSU LKM，
> `su` 返回 `uid=0 ... u:r=ksu:s0`，且系统/其它 App 正常运行。

## 1. 最终可用流程（一次干净开机）

```
1) 用 CVE-2026-99491（wacom HID sibling touch_input UAF）拿到 fixed-word 写原语
2) 泄漏本进程 cred（tracefs kmem_cache_alloc raw ring），固定词写：
   euid/uid/gid/egid=0、fsuid=0、cap_effective bit16(CAP_SYS_MODULE)
3) 开 SELinux permissive 窗口：**zero word 写到 selinux_state-7**（只把 enforcing 字节置 0）
4) ko 后端加载 KernelSU：
   - 用本机 link-time kallsyms 把 kernelsu.ko 的所有 UND 符号改成 SHN_ABS
     （st_value = link + KASLR slide），memfd + finit_module(fd, "allow_shell=1", 0)
   - finit 之前把 ksud 复制到 /data/adb/ksud（KSU sucompat 前提）
5) 模块 init 后 KernelSU 自己把 SELinux 恢复 Enforcing；exp 走成功路径，不做任何 restore 写
6) 验收：/proc/modules 出现 kernelsu Live；`/system/bin/su -c id` = uid=0 + u:r=ksu:s0
   （若 context=kernel 也属可用降级，但本机修复后是 ksu）
```

## 2. 三个关键坑与修复（按重要性）

### 坑 A：`ksud late-load` 不能"先 exec 再指望它"——能力在 exec 时丢失
伪造 cred 后 `execve(ksud)`，按 Linux capabilities 语义
`P'(permitted)=P(inheritable)|P(bounding)`；本机 `CapBnd=0x8000c0`，不含
CAP_SYS_MODULE(16) → ksud 执行后连 `init_module` 的权限都没有，必然失败（而且
ksud 的 ksuinit 还要读 `/proc/kallsyms`，本机 `kptr_restrict=2` 需要 CAP_SYSLOG）。
**修复**：ko 后端不 exec，直接在提权子进程里 `finit_module`，保住 CapEff bit16。

### 坑 B（App 打不开的真因）：开窗不能污染 `selinux_state` 内部字段
KernelSU 在 late-load 模式下，模块 init 会调用 `apply_kernelsu_rules()`
（`kernel/core/init.c` + `kernel/selinux/rules.c`），它要 dup/替换
`selinux_state.policy`、重置 AVC、使用结构体内 mutex。
旧写法在 `selinux_state-1` 写 V1 词（8 字节），会把 `enforcing` 之后的
`initialized`、后续标志字节一起改写 → 策略注入失败 → dmesg
`SELinux: security_sid_to_context_core: called before initial load_policy on unknown SID`
+binder 取上下文失败 → 所有新 App 打不开，`su` 只能停在 `context=kernel`。
**修复**：按 98260 链同款做法，写 **zero word 到 `selinux_state-7`**：8 字节里只有
`enforcing`（结构体第 0 字节）被置 0，`initialized` 及其后字段、`policy` 指针、
mutex 全部保持原值；前面 7 字节落在结构体外的锁对象上，置 0 等价于 unlocked，安全。
加载完成后 KSU 自己把 Enforcing 设回 1。

### 坑 C：失败路径的"恢复"会二次破坏
旧 restore 在 `selinux_state-2` 写 V1 词，会把 `initialized` 写成 0（同样导致 App 打不开）。
**修复**：加载成功的路径用 `CVE99491_SKIP_SU_CHECK=1` 跳过 exp 内部 su 检查，
让 exp 走成功路径、不做 restore；permissive 的关闭交给 KSU。

## 3. 模块来源与符号表

- KO：`ksud` 内嵌的 `android17-6.18_kernelsu.ko`（可用 `ksud debug extract-binary` 导出；
  实测与 ChaYeWuu/XRING-CVE-2026-99491 的 `kernelsu-violin.ko` 同 sha256
  `d848bcbeb3f4daffeea4b2ad2d70aac8f79211ce9f15f200dd87c7b8d68ebe30`）。
- vermagic `6.18.32…` 与本机 `6.18.21…` 不同仍可加载：Android GKI 只比对
  SMP/preempt/mod_unload/modversions/aarch64 标志；且所有 UND 符号被改成
  `SHN_ABS` 后内核跳过符号解析与 modversions CRC 校验。
- 符号表：用本机真机 root 导出的 link-time kallsyms（临时 `kptr_restrict=0` 后立即恢复）
  生成 `plant/99491/ksu_symbols.inc`；该 KO 的 225 个 UND 符号全部命中（missing=0）。
- 运行时若内核 release 与 profile 不符，exp 会 fail-closed 拒绝加载（防止 OTA 后错地址写飞）。

## 4. 真机证据（关键一次，干净开机）

```
[ko] ksud installed src=/data/local/tmp/ksud dst=/data/adb/ksud bytes=4990848
[ko] image=/data/local/tmp/kernelsu-android17-6.18.ko size=375328
[ko] patched=225 missing=0 slide=0x1771600000
[ko] finit_module result=0 errno=0 (ok)
MODULE_LOADED
[f] module_live=1 enforce=1
su context: uid=0(root) gid=0(root) groups=0(root) context=u:r=ksu:s0
Enforcing
```
用户确认：运行后**其它 App 可以正常打开**。

失败对照（同一台机、同一 KO、旧开窗写法）：
`finit_module result=0` 但 dmesg 出现 `unknown SID ... called before initial load_policy`，
`su` 只有 `context=kernel`，所有 App 打不开。

## 5. 复盘与经验

见 [`docs/99491-retrospective.md`](99491-retrospective.md)：为什么花了这么久、原因、技术难点、最后的解决路径与可复用经验清单。

## 6. 设备侧复现（LHASA Harness 脚本）

`/sdcard/Download/DSH-Go/99491/`：
- `exp_direct_root`（sha256 `b6e67810402eb115490cb3d22c67a00dfcd7caabad731b795867302fce167bd9`）
- `run_stage.sh`（ROOT19：基线/加载后 App 健康检查 + su context + dmesg）
- `/data/local/tmp/cve99491/{exp,profile.json}`、`/data/local/tmp/{ksud,kernelsu-android17-6.18.ko}`

环境变量：`CVE99491_KSU_BACKEND=ko CVE99491_KSUD_BIN=/data/local/tmp/ksud
CVE99491_KSU_KO=/data/local/tmp/kernelsu-android17-6.18.ko
CVE99491_SKIP_SU_CHECK=1`

## 6. 参考

- KernelSU late-load / ksuinit / apply_kernelsu_rules 源码：<https://github.com/tiann/KernelSU>（v3.3.1）
- 同家族漏洞实现：<https://github.com/ChaYeWuu/XRING-CVE-2026-99491>
- Android Kernel SELinux bypass（enforcing 是正确目标、initialized 属高危目标）：
  <https://hacktricks.wiki/en/binary-exploitation/linux-kernel-exploitation/android-kernel-selinux-bypass.html>
- late-load 后 fsec 重置：<https://github.com/Baka-SU/BakaSU/commit/9ca4023bc31e88b8f4a84eed285d9626e245b35b>

## 7. 后续

- App 端资产更新为修复版 exp 并重建 APK（本文件同 commit 完成后进行）
- 3 次冷启动复现（S7）、98260 回归、fail-closed 实测、CI 出包
