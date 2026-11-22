# plant 目录说明

## 现状（2026-11-22 晚）

| 资产 | 源码 | 许可 |
|---|---|---|
| `reach_probe` | `plant/reach_probe.c` | 自有 |
| `slide_probe` | 上游 `src/xr98260_slide_probe.c` | MIT |
| `pc98260-su` | 上游 `src/pc98260_su.c` | MIT |
| `uaf_plant_replay` | 上游 `src/exploit-android-perf.c` | MIT |
| `ksud` | KernelSU v3.3.1 `libksud.so` | GPL-3.0 |

上游 = `Lw5959/xring-cve-2026-98260`，版本锚定在 `tools/xring.lock.properties`
（commit + tarball sha256），由 `tools/build_xring.sh` 下载校验后交叉编译。

`perf_slide` 已移除：本 ROM 的 SELinux 对 `u:r:shell:s0` 拒绝
`perf_event` 的 `{ kernel }` 权限，perf 内核采样在此环境不可用。

## 两条分发通道

**A. 直接上机测（秒级）**：publish 会把产物写成 `plant/out/<名字>.b64`

```sh
base64 -d /sdcard/Download/<名字>.b64 > /data/local/tmp/<名字>
chmod 755 /data/local/tmp/<名字>
timeout 10 /data/local/tmp/<名字>
```

**B. 装 APK**：提交信息带 `[release]` 才出包，只在验 App 调度时需要。

## 上游的关键实现（我们重写时踩过的坑）

- **slide 来源**：扫 `per_cpu/cpuN/trace_pipe_raw` 的**二进制记录**，从
  `call_site - profile.alloc_timer_site` 得到 2 MiB 对齐的 slide。
  我们之前的文本解析永远拿不到 `call_site`。
- **su 协议**：`uint32 长度前缀 + 命令`；长度 0 时进入 stdin↔socket 交互模式。
  少了前缀就和真 rootd 对不上。
- **载体**：用 AF_UNIX `SOCK_STREAM` 写 8192 字节命中 order-1 的
  `posix_timers_cache`（pipe/AIO 这类 order-0 分配很难命中 8 KiB slab）。
- **命中判据**：victim `cpu_timer.node` 所在 4 KiB 半页的 pfn，再 `& ~1`。

## 真机踩过的坑

| 现象 | 真因 |
|---|---|
| `perf_event_open` → `errno=13 EACCES` | SELinux 只允许用户态 perf；`{ kernel }` 被拒 |
| `errno=7 E2BIG` | `attr.size` 用了 `sizeof(struct perf_event_attr)` |
| 装载 vermagic 不匹配的内核模块后整机硬复位 | 平台无 pstore，重启后 `bootreason` 仍是 `AP_S_COLDBOOT,NA` |
| `/proc/kallsyms` / `kprobe_events` 对 shell 不可用 | 该 ROM 直接拒绝，不是显示 0 |
| `--duration 1` 采不到样本 | 调用方按秒传参，实现别按毫秒写 |

## 语义约定

- `--slide`：`运行时 - 链接期` 的差值，2 MiB 对齐（`KernelSupport.isSlideValid`）。
- `reach_probe` 有失败时退出码是 **2**（原件行为）。
- `slide_probe` 输出 `site=0x… slide=0x…`，并带 `timers=` / `raw_bytes=` 行。
