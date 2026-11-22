# 真机观测记录（原件行为基线）

记录的是 `app/src/main/assets/` 里**原件**在目标机上的实际表现。
为什么单独存一份：从字符串反推行为会错得离谱（见下面的 `slide_probe`），
真机跑一次的输出比一百行推断都准。

> 2026-11-22 起，`reach_probe` / `slide_probe` / `perf_slide` / `pc98260-su` 已替换为
> `plant/*.c` 编译出的自有产物（台账 `status: rebuilt`）。本文件记录的是**替换前**原件的
> 行为，作为等价性比对的参照；`uaf_plant_replay` 与 `ksud` 保持原样。

## 环境

| 项 | 值 |
|---|---|
| 机型 | `lhasa` / 2608BPX34C |
| 内核 | `6.18.21-android17-5-g284297031c53-abogki553682993-4k`（在 `KernelSupport.SUPPORTED_KERNELS` 里） |
| 系统增量 | `OS4.0.21.0.XPNCNXM` |
| SELinux | Enforcing（提权前） |
| 提权 | 工作流跑通后 `su -c id` → `uid=0(root) ... context=u:r=ksu:s0` |

观测日期：2026-11-22。

## `reach_probe`（原件，root 下执行，退出码 2）

```
=== CVE-2026-98260 / lhasa 环境诊断（重写版）===
  uname -r        : 6.18.21-android17-5-g284297031c53-abogki553682993-4k
  kernel version  : #1 SMP PREEMPT Mon Aug 31 02:13:04 UTC 2026
  ro.product.device: lhasa
  ro.product.model : 2608BPX34C
  系统增量         : OS4.0.21.0.XPNCNXM
  getenforce      : Enforcing
  id              : uid=0(root) gid=0(root) groups=0(root),2000(shell) context=u:r:ksu:s0

--- 内核信息泄露面 ---
  [ OK ] /proc/slabinfo 可读                    open ok
  [ OK ] /proc/kallsyms 可读                    ok
  [ OK ] /proc/self/pagemap                       present=1

--- tracefs（决定整条链能否观测）---
  [ OK ] /sys/kernel/tracing 存在               access
  [ OK ] tracing_on 可写                        write ok
  [ OK ] kmem/rss_stat/trigger 可写             write ok
  [ OK ] kmem_cache_alloc/enable 可写           open ok
  [ OK ] per_cpu/cpu0/trace_pipe_raw 可读       access
  [ OK ] kprobe_events 存在                     access

--- 系统调用面 ---
  [ OK ] timer_create(CLOCK_THREAD_CPUTIME)       ok
  [ OK ] io_setup (AIO)                           ok
  [ OK ] unix SOCK_STREAM 8KB write               ok
  [FAIL] perf_event_open (software)               errno=7 (Argument list too long)

--- 结论 ---
  12 ok / 1 fail
  有 1 项未通过，先看上面标 FAIL 的项。
```

要点：
- 行首是 `[ OK ]`（**带空格**）与 `[FAIL]`（**不带**），不是统一格式。
- 有失败时退出码 **2**。
- `perf_event_open` 用 `sizeof(perf_event_attr)` 传参，6.18 内核返回 `E2BIG(errno=7)`。
  这是原件的已知误报，`WorkflowEngine.runDiagnosis()` 里用 `perf_slide` 复核覆盖它。
  `plant/reach_probe.c` 按原样复现该行为，以保持等价。

## `slide_probe`（原件，root 下执行，退出码 0）

```
[slide] cpu0    SensorService-15180   [000] .....  1405.055564: kmem_cache_alloc: call_site=alloc_skb_with_frags+0x88/0x510 ptr=00000000ea05806f name=skbuff_head_cache bytes_req=248 bytes_alloc=256 gfp_flags=GFP_KERNEL_ACCOUNT node=-1 accounted=true
[slide] cpu4      slide_probe-3216    [004] .....  1405.055569: kmem_cache_alloc: call_site=alloc_posix_timer+0x30/0xa4 ptr=00000000ff6c1074 name=posix_timers_cache bytes_req=384 bytes_alloc=384 gfp_flags=GFP_KERNEL|__GFP_ZERO node=-1 accounted=true
...（共 22 行，含 rss_stat 与 kmem_cache_alloc 事件）
[slide] lines=22
[slide] raw cpu0 bytes=4096 hits=0
[slide] raw cpu1 bytes=0 hits=0
[slide] raw cpu2 bytes=0 hits=0
[slide] raw cpu3 bytes=4096 hits=0
[slide] raw cpu4 bytes=4096 hits=0
[slide] raw cpu5 bytes=0 hits=0
[slide] raw cpu6 bytes=0 hits=0
[slide] raw cpu7 bytes=0 hits=0
```

要点（上一版实现全踩反了）：
- 每一行 trace **原样**打印，前缀 `[slide] cpu<idx> `；
- 命中判定看 slab 名 —— 目标是 `posix_timers_cache` / `bytes_req=384`，**不是** `site=`/`ptr=`；
- 那次 `hits` 全为 0，说明触发器窗口里没有目标对象分配，属正常空跑。

## `perf_slide`（原件）—— 危险，必须加超时

`perf_slide --period 1000 --duration 300` 在 root 下**超过 120 秒未返回**，
随后设备重启。推测是 1 kHz 采样 + 64 页 ring 在内核侧形成持续压力，
看门狗把 `system_server` 拖进 soft lockup。

因此：
- 任何采样器必须用 `timeout` 包起来（`BootGuard.withTimeout`，perf 8 s / slide 12 s）；
- 不要在真机上人工跑不带 `timeout` 的 `perf_slide`；
- `--duration` 的语义尚未确定（它显然不是"多少毫秒后退出"），需要单独用 5 s 上限试探。

## 由此产生的待办

1. `perf_slide` 的 `--duration` 语义待定；在真机上只能用 `timeout 5` 试探。
2. 四个自有产物的闸 2（成对执行比对）需要在重开 Shizuku、重新取得临时 ROOT 后进行。
3. `uaf_plant_replay` 无源码，维持不可重建结论（见 `tools/assets-ledger.json`）。
