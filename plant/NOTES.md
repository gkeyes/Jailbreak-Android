# plant 目录说明

## 现状（2026-11-22 晚）

| 资产 | 源码 | 许可 | 说明 |
|---|---|---|---|
| `reach_probe` | `plant/reach_probe.c` | 自有 | 唯一仍由我们重写的探针 |
| `slide_probe` | 上游 `src/xr98260_slide_probe.c` | MIT | 扫 `trace_pipe_raw` 二进制记录求 slide |
| `pc98260-su` | 上游 `src/pc98260_su.c` | MIT | 先写 uint32 长度、再写命令 |
| `uaf_plant_replay` | 上游 `src/exploit-android-perf.c` | MIT | CLI 仍为 `--slide/--site/--timer` |
| `ksud` | KernelSU v3.3.1 `libksud.so` | GPL-3.0 | 上游预编译，钉版本 + 双层哈希 |

上游 = `Lw5959/xring-cve-2026-98260`，锚定在 `tools/xring.lock.properties`
（commit + tarball sha256），由 `tools/build_xring.sh` 下载校验后交叉编译。

`perf_slide` 已移除：本 ROM 的 SELinux 对 `u:r:shell:s0` 拒绝
`perf_event` 的 `{ kernel }` 权限，perf 内核采样在此环境不可用。

## 协议要点（来自上游源码）

- `pc98260_su`：`write(uint32 len)` → `write(cmd bytes)` → 读回显。
  长度 0 时进入 stdin ↔ socket 全双工模式（无 `-c` 参数时）。
  `connect` 失败才输出 `perror("connect root daemon")`。
- `xr98260_slide_probe`：pin cpu0 → 开 `kmem:kmem_cache_alloc` 触发器 →
  建 64 个 posix timer → 扫每 CPU 的 `trace_pipe_raw`，找
  `call_site - profile.alloc_timer_site` 为 2 MiB 对齐且 `bytes_req == kitimer_bytes`
  的记录 → 输出 `site=0x… slide=0x…`。
- `exploit-android-perf`：拿 `--slide` 后按 profile 加出 timer/cred/selinux/task
  的运行时地址，做 order-1 页复用 + cred 植入，最后起 rootd。

## 两条分发通道

**A. 直接上机测（秒级）**：publish 会把产物写成 `plant/out/<名字>.b64`

```sh
base64 -d /sdcard/Download/<名字>.b64 > /data/local/tmp/<名字>
chmod 755 /data/local/tmp/<名字>
timeout 10 /data/local/tmp/<名字>
```

**B. 装 APK**：提交信息带 `[release]` 才出包，只在验 App 调度时需要。

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
