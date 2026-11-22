# plant 目录说明

## 两条分发通道

**A. 直接上机测（秒级）**
publish 会把产物写成 `plant/out/<名字>.b64`。设备上：

```sh
base64 -d /sdcard/Download/<名字>.b64 > /data/local/tmp/<名字>
chmod 755 /data/local/tmp/<名字>
timeout 10 /data/local/tmp/<名字> --duration 1
```

**B. 装 APK**：提交信息带 `[release]` 才会出包，只有验 App 调度时才需要。

## 产物来源

| 资产 | 源码 | 许可 |
|---|---|---|
| `reach_probe` | `plant/reach_probe.c` | 自有 |
| `perf_slide` | `plant/perf_slide.c` | 自有 |
| `slide_probe` | 上游 `src/xr98260_slide_probe.c`（钉版） | MIT |
| `pc98260-su` | 上游 `src/pc98260_su.c`（钉版） | MIT |
| `uaf_plant_replay` | 上游（尚未切换） | MIT |
| `ksud` | KernelSU v3.3.1 的 `libksud.so` | GPL-3.0 |

上游版本锚定在 `tools/xring.lock.properties`（commit + tarball sha256），
由 `tools/build_xring.sh` 下载校验后交叉编译。

## 为什么 slide_probe / pc98260-su 换成上游

- 我们重写的 `slide_probe` 用**文本**解析 trace，拿不到 `call_site` 地址，
  命中恒为 0；上游扫的是 `per_cpu/cpuN/trace_pipe_raw` 的**二进制记录**，
  用 `call_site - profile.alloc_timer_site` 得到 2MiB 对齐的 slide。
- 我们重写的 `pc98260-su` 直接写「命令 + 换行」；上游协议是
  **uint32 长度前缀 + 命令**，长度 0 时进入交互模式（stdin ↔ socket）。

## 真机踩过的坑

| 现象 | 真因 |
|---|---|
| `perf_event_open` → `errno=13 EACCES` | SELinux 只允许用户态的 perf；`{ kernel }` 被拒（`tclass=perf_event`） |
| `errno=7 E2BIG` | `attr.size` 用了 `sizeof(struct perf_event_attr)`；应 `PERF_ATTR_SIZE_VER5` |
| `perf_slide --duration 1` 采不到样本 | 调用方按**秒**传参，实现按毫秒写等于 1 毫秒 |
| `slide_probe` 命中 0 | 文本解析 trace 拿不到 call_site，必须扫二进制记录 |
| `/proc/kallsyms` / `kprobe_events` 不可用 | 该 ROM 对 `u:r:shell:s0` 直接拒绝 |
| 装载 vermagic 不匹配的 kernel module 后整机硬复位 | 平台无 pstore，重启后 `bootreason` 仍是 `AP_S_COLDBOOT,NA` |

## 语义约定

- `perf_slide --duration N`：**秒**，实现里夹在 1..8。
- `--slide`：`运行时 - 链接期` 的差值，2MiB 对齐（`KernelSupport.isSlideValid` 判据）。
- `slide_probe` 现在输出 `site=0x… slide=0x…`（上游格式，含 `timers=`/`raw_bytes=` 行）。
- `reach_probe` 有失败时退出码是 **2**。
