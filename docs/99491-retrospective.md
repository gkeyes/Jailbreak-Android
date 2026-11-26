# CVE-2026-99491 第二条提权链：复盘与经验（为什么花了这么久）

> 一句话结论：**技术难点不在"拿到写原语"或"加载模块"，而在"加载后不破坏 SELinux 状态"**；
> 我们绝大部分时间耗在最后这一点上，而它本来可以通过**先读 KernelSU 源码 + 对比 98260 成功路径**
> 在离线阶段定位，不需要反复上真机。

## 零、最大的问题：我们把 `selinux_state` 写坏了（必须单独写清）

> 这是整个项目里**最严重、也最耗时**的问题，而且**责任在我们自己**：不是内核/Android 的 bug，
> 也不是"越狱必然导致 App 打不开"，而是**我们的开窗写法破坏了 KSU 初始化所依赖的内核状态**。

### 0.1 具体做了什么、破坏了什么

1. 为了打开 SELinux permissive 窗口，我们用 fixed-word 写原语直接改内核内存里的
   `struct selinux_state`；
2. 该原语**一次只能写固定 8 字节词组，不能只写 1 个字节**；
3. 旧写法把词组打在 `selinux_state-1`：
   - 目的字节 `enforcing` 确实被写成 0（`getenforce` 变 Permissive，窗口"看起来成功了"）；
   - **但同一个词组的另外 7 个字节覆盖了 `initialized` 及后面的字段字节**；
   - 失败路径的"恢复"又把这个区域二次改写，把 `initialized` 写成 0。
4. KernelSU 在 late-load 模式下加载模块时，会在模块 init 里调用
   `apply_kernelsu_rules()`：dup/替换 `selinux_state.policy`、重置 AVC、用到结构体内的锁；
   它要求 `selinux_state` 处于**干净一致**状态（`initialized=true`、`policy` 指针与 mutex 完好）；
5. 结构体被污染 → 策略重建失败 → 内核报
   `SELinux: security_sid_to_context_core: called before initial load_policy on unknown SID`，
   binder 取不到安全上下文 → **zygote 无法为新 App 设置域 → 所有 App 打不开**；
   `su` 也因为 ksu 域没有正确建立，只能停在 `context=kernel`。

### 0.2 这是谁的问题？

- **是我们的方法问题**：写原语的粒度（8 字节）与目标偏移选择（`-1`）不匹配结构体布局，
  导致越界覆盖；属于"primitive 太粗 + 目标选错"。
- **不是底层系统 bug**：同一台机、同一内核、同一 Android，修正写入位置后完全正常
  （`su=u:r=ksu:s0`、App 正常打开）。
- **不是"越狱必然破坏系统"**：98260 参考路径同样开 permissive 窗口，但它只改 `enforcing`
  一个字节，所以不破坏策略初始化。

### 0.3 有没有造成永久损坏？

**没有。** 我们只改了**内存中的内核状态**（`selinux_state` 与临时 LKM）：

- 没有写分区、没有改 boot/系统文件、没有刷机、没有动 `/data/adb` 之外的数据；
- 重启后内核重新初始化、LKM 消失，系统完全恢复（后续真机验证 App 正常、KSU 状态消失）；
- 影响范围仅限"被写坏的那次开机"，代价是**必须重启**。

### 0.4 正确做法（最终采用）

- 把**零词组**打到 `selinux_state-7`：8 字节里**只有 `enforcing` 这一个字节落在结构体内**；
  `initialized`、`policy`、mutex 全部保持原值；前面 7 字节落在结构体外的锁对象上，
  置 0 等价于 "unlocked"，安全；
- 加载成功后**不做任何 restore 写**（`CVE99491_SKIP_SU_CHECK=1`），交给 KernelSU 自己恢复 Enforcing；
- 结果：`finit_module result=0`、模块 Live、`su=u:r=ksu:s0`、其它 App 正常。

### 0.5 这件事的教训（写进 checklist）

1. **改内核结构体前必须先拿到准确布局**（BTF/符号表/源码），并计算"这次写会覆盖哪些字节"；
2. **能用最小覆盖就不要用大覆盖**：能只改 1 字节就绝不用 8 字节词覆盖半个结构体；
3. **写完之后用外部状态验证**（`/proc/modules`、`su -c id` 的域、dmesg、能否新起进程），
   不要因为 `getenforce=0`/`finit=0` 就认为成功；
4. **对内核状态的写入必须有"恢复策略"**，并明确"这次写给系统留下了什么副作用、是否需要重启"。

## 一、时间到底花在哪

| 阶段 | 内容 | 评价 |
|---|---|---|
| A. 第一路径修复/发布 | 让 `next` 分支 APK 构建变绿、发 0.4.1-dev | 必要、顺利 |
| B. 99491 从 0 到写原语 | tracefs 抓 cred（6.18 布局）、KASLR、UAF 回收、fixed-word 写 | 困难但线性推进，属正常成本 |
| C. `ksud late-load` 静默失败 | 无输出 rc=0、daemonize、logcat、kptr_restrict/CAP_SYSLOG、exec 后 caps 丢失 | **第一段弯路**：没有先读 `ksuinit`/`ksud` 源码 |
| D. ko 后端 + `finit_module` | patch ELF UND→SHN_ABS、memfd、flags=0、Enforcing 下 EPERM | 技术密度高，但结论明确 |
| E. **"加载成功但 App 全打不开"** | 旧开窗写法污染 `selinux_state`，KSU 策略注入失败 | **最大时间黑洞**：约占总时间一半以上 |
| F. App 集成与参数 bug | 相对 `--workdir`、分类误判、签名/安装 | 收尾细节 |

真机轮次约 20+ 次、重启约 20 次；其中大部分集中在 E 阶段。

## 二、为什么会这样（原因分析）

1. **先猜后验，而不是先读源码**
   - `ksud late-load` 失败时，我们先后猜过"asset 缺失""KMI 错误""权限不足"。
   - 实际上 KernelSU 源码里写得很清楚：`ksuinit` 读 `/proc/kallsyms`（需要 CAP_SYSLOG）、
     late-load 模式下模块 init 会调用 `apply_kernelsu_rules()` 重建 SELinux policy。
   - 教训：**对上游组件的行为，先读源码/文档，再设计实验**。

2. **没有做单变量隔离**
   - 失败时同时存在多个变量：KO 版本、开窗写法、ksud 收尾、App 参数、模块参数。
   - 每次真机实验改多个点，失败后无法归因，只能再试一次（每次都要重启）。

3. **可观测性差，证据会丢**
   - exp 输出被 stdio 全缓冲，卡死时看不到最后一行走到了哪；
   - 用 `timeout`（SIGTERM）杀 exp 无效（exp 自己忽略了信号）→ 脚本"永远执行中"；
   - 系统被写坏后 `/sdcard` 挂载也会失效，日志再也取不出来；
   - 后来才改成：**无缓冲输出 + 实时写 `/sdcard` + `kill -9` 兜底 + 失败前先把证据落盘**。

4. **信任了"看起来成功"的信号**
   - `ksud late-load` 无输出 + rc=0（其实只是 daemonize 了）；
   - `finit_module result=0`（模块进了内核，但策略初始化失败）；
   - `MODULE_LOADED`（模块 Live，但 `su` 只有 `context=kernel`）。
   - 正确的是用**外部可观测状态**验收：`/proc/modules`、`su -c id` 的域、dmesg、能否打开新 App。

5. **把试错成本转嫁给了用户**
   - 每次"重启一次再跑"都是用户的实际成本；应在下真机前把离线能做的验证做足
     （源码阅读、离线模拟、单变量设计、脚本自检）。

## 三、真正的技术难点

1. **无 kprobe 的 6.18 内核上做信息泄露**
   - 本机 `kprobe_events` 被 miuibpf 占用（EBUSY），只能用 tracefs `kmem_cache_alloc` 原始环形缓冲；
   - 6.18 tracepoint 记录布局与 5.15 不同（`__string(name)` 导致偏移变化），解析写错过一次。

2. **fixed-word 写原语的能力约束**
   - 只能写固定 8 字节词（EV_SW 词 / 零词组），不能任意写；
   - 因此"把某个结构体字段改成一个特定值"往往不可行，必须利用词内字节布局+目标偏移组合。

3. **SELinux 状态机的脆弱性**
   - 开 permissive 最直接的做法是写 `selinux_state.enforcing`，但结构体字段密集、部分结构 `__randomize_layout`；
   - 写偏一个字节（哪怕只是给 `initialized` 写了个"真值"）都会在 KSU late-load 重建策略时炸掉；
   - 我们最终的做法：**zero word 打在 `selinux_state-7`**，8 字节里只有 `enforcing` 落在结构体内，
     `initialized`/`policy`/mutex 全不动；前面 7 字节落在结构体外的锁对象上，置 0 等于 unlocked。

4. **KernelSU late-load 的隐蔽行为**
   - `ksu_late_loaded = (current->pid != 1)`：late-load 不是"普通 insmod"；
   - 它会在模块 init 阶段 `apply_kernelsu_rules()`：dup/替换 `selinux_state.policy`、重置 AVC；
   - 所以**加载时的 SELinux 状态必须干净**，否则策略注入失败 → `unknown SID` → 新进程起不来、App 全打不开。

5. **exec 会丢能力（capabilities 语义）**
   - 伪造 cred 后 `execve(ksud)`，`P'(permitted)=P(inheritable)|P(bounding)`；
   - 本机 `CapBnd=0x8000c0` 不含 CAP_SYS_MODULE(16) → ksud 执行后没有加载模块的权限；
   - 结论：**加载动作不能 exec**，必须在提权进程里直接 `finit_module`。

6. **行为一致但"版本不同"的 KO**
   - 我们的 KO vermagic 是 6.18.32，本机 6.18.21；
   - Android GKI 只比对 flags，且所有 UND 符号被改成 `SHN_ABS` 后内核跳过符号解析与 CRC 校验，所以能加载。

7. **App 端状态机与 fail-closed**
   - 普通 App 只能通过 Shizuku 以 shell 身份执行；一旦内核被写，**本 boot 不能再试**；
   - 因此需要严格分级：写前失败→自动回退 98260；写后失败/PARKED→dirty、必须重启、绝不重试。

## 四、最后的解决路径（关键 insight）

**失败链**：旧开窗写法 `selinux_state-1` 写 V1 词 → 覆盖 `enforcing` 之后多个字节 → 
KSU `apply_kernelsu_rules()` 在坏状态上重建策略失败 → `unknown SID` / binder 取不到上下文 →
App 全打不开、`su` 只能停在 `kernel`。

**转折点（为什么想到）**：
1. 看到 dmesg 的 `security_sid_to_context_core: called before initial load_policy`，说明 `initialized` 被破坏；
2. 读 KernelSU 源码，确认 late-load 分支会 `apply_kernelsu_rules()` 重建策略，对加载时状态极度敏感；
3. 对比 98260 成功路径：它开窗用的是 **`selinux_state-7` 的零词组**，只把 enforcing 置 0；
4. 查阅公开资料（HackTricks SELinux bypass）：`enforcing` 是正确目标，`initialized` 属于"高危、不可碰"的目标；
5. 于是把开窗改成同款零词组，并让 exp 成功路径不做任何 restore（`CVE99491_SKIP_SU_CHECK=1`，交给 KSU 自己恢复 Enforcing）。

**结果**（干净开机一次通过）：
```
[ko] patched=225 missing=0 -> finit_module result=0
MODULE_LOADED / [f] module_live=1 enforce=1
su -c id = uid=0 ... u:r=ksu:s0
用户确认其它 App 正常运行
```

## 五、可复用的经验清单

1. **先读源码/上游文档，再上真机**；对 KernelSU 这类复杂组件，先搞清楚它做了什么、依赖什么。
2. **单变量隔离**：每次真机实验只改一个变量，并为失败准备可判读的日志。
3. **证据先行**：输出无缓冲、实时落盘；关键日志写到"系统坏掉后仍可读"的地方；失败前先 dump dmesg。
4. **用外部状态验收，不信表面标记**：`/proc/modules`、`su -c id` 的域、dmesg、能否新起进程。
5. **最小扰动地改内核状态**：先明确结构体布局（BTF/符号表）、只改必要字段、保留其它字节；
   能用"只改一个字节"就绝不用 8 字节词覆盖半个结构体。
6. **弄清权限模型**：exec 会丢 caps；不同关键操作需要什么 cap（CAP_SYS_MODULE / CAP_SYSLOG / CAP_MAC_ADMIN）
   要在设计阶段列清楚。
7. **fail-closed 前置设计**：每次内核写都有重启代价；把"写前可回退、写后禁重试"做进状态机。
8. **不要省单变量验证的时间**：这一次真正省下来的时间，不是更快地试，而是**更早地读源码和对比成功路径**。

## 六、如果重来（缩短路径）

1. 第一天：读 KernelSU `late_load.rs` / `init.c` / `ksuinit` / `selinux_hide.c`，列出加载前置条件；
2. 同时拉一份 98260 成功路径的完整日志，对齐"它做对了什么"；
3. 用 BTF 打印 `selinux_state` 布局，设计"只改 enforcing"的写入；
4. 离线模拟 ko patch + 单测，再上真机；
预计可以把 E 阶段从"十几次真机轮次"压到 **2~3 次**。

## 七、参考

- KernelSU v3.3.1：<https://github.com/tiann/KernelSU>
  （`userspace/ksud/src/late_load.rs`、`userspace/ksuinit/src/lib.rs`、`kernel/core/init.c`、`kernel/selinux/rules.c`）
- 同家族漏洞实现：<https://github.com/ChaYeWuu/XRING-CVE-2026-99491>
- HackTricks · Android Kernel SELinux Bypass：
  <https://hacktricks.wiki/en/binary-exploitation/linux-kernel-exploitation/android-kernel-selinux-bypass.html>
- BakaSU late-load fsec 修复：<https://github.com/Baka-SU/BakaSU/commit/9ca4023bc31e88b8f4a84eed285d9626e245b35b>
