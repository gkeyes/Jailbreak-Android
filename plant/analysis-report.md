# payload 常量扫描

由 CI 从 `app/src/main/assets/` 里的二进制直接扫描得出，未执行任何代码。

## uaf_plant_replay

`88488` bytes，内核地址立即数 `10` 个。

| addr | off | hits | note |
|---|---|---|---|
| `0xfffffffc7fffffff` | `0x1bc8` | 1 |  |
| `0xffffffd400000004` | `0x20ac` | 1 |  |
| `0xffffffc0803a726c` | `0x155a8` | 1 |  |
| `0xffffffc08026d1b4` | `0x155b0` | 1 |  |
| `0xffffffc082959630` | `0x155b8` | 1 | profile selinux |
| `0xffffffc0801f006c` | `0x155c0` | 1 |  |
| `0xffffffc0826d10d8` | `0x155c8` | 1 | profile userns |
| `0xffffffc0826d2a48` | `0x155d0` | 1 | profile groups |
| `0xffffffc0826d2f08` | `0x155f0` | 1 | profile ucounts |
| `0xffffffc0826d1388` | `0x155f8` | 1 | profile rootuser |

日志标记 / 关键字：

```text
selinux
/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw
/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw
[selinux] enforce=%s
[cred] answer %s
[cred] proc %s
[child-cred] %s
--slide
/sys/fs/selinux/enforce
[profile] timer=%#lx cred=%#lx selinux=%#lx task=%#lx userns=%#lx groups=%#lx
[cfg] timer=%#lx cred=%#lx selinux=%#lx task=%#lx
[cfg] timer=%#lx cred=%#lx selinux=%#lx task=%#lx site=%#lx
[cred] installed at %#lx
[slide] %#lx
[cred] node=%#lx task+cred=%#lx off=%#x
[cred] plant does not fit off=%#x
[uaf] captured=%d chosen=%#lx raw=%zu
[cred] still uid=%u euid=%u
[cred] child %d stayed silent
[selinux] attempt %d/6 target=%#lx kill_delay=%uus
[cred] rooted via cred+8/+16 fixups
[cred] child=%d holding pages
[cred] child did not answer
[selinux] 3 hits without effect, stop
[cred] 6 consecutive misses, stop
[selinux] 3 consecutive misses, stop
[cred] 3 attempts installed but not rooted, stop
[selinux] already permissive
[child-cred] wake closed, holding pages idle
[uaf] missed page; holding zombie
[cred] SELinux still enforcing, skip cred stage
[cred] blob overlaps node
[task] leak failed
[child-cred] answer errno=%d
[cred] ask write errno=%d
[cred] answer read errno=%d
[selinux] enforce read errno=%d
[cred] child %d is dead errno=%d
[rootd] listening at %s pid=%d
[child-cred] waiting pid=%d
[uaf] ring=%zu KiB read_cap=%zu MiB
[cred] plant attempt %d/8
[rootd] startup failed errno=%d (%s)
Broken pipe
```

## perf_slide

`31840` bytes，内核地址立即数 `1` 个。

| addr | off | hits | note |
|---|---|---|---|
| `0xffffffd400000a29` | `0x3b8` | 1 |  |

日志标记 / 关键字：

```text
slide=0x%llx
[perf] best votes=%d/%d slide=%#lx
[perf] no slide candidate
[perf] no kernel frames leaked
[perf] candidates=%d
[perf] samples=%d kernel_frames=%d
[perf] mmap failed errno=%d
[perf] no usable hardware PMU errno=%d
[perf] hardware cycles open failed errno=%d (%s)
Broken pipe
```

## slide_probe

`44776` bytes，内核地址立即数 `2` 个。

| addr | off | hits | note |
|---|---|---|---|
| `0xfffffffc7fffffff` | `0x1028` | 1 |  |
| `0xffffffd4fffffffc` | `0x102c` | 1 |  |

日志标记 / 关键字：

```text
/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw
[slide] cpu%d %s
[slide] raw cpu%d site=%#lx ptr=%#lx
[slide] raw cpu%d bytes=%zu hits=%d
[slide] lines=%d
[slide] timer_create errno=%d
Broken pipe
```

## pc98260-su

`28416` bytes，内核地址立即数 `0` 个。

无匹配（可能是位置无关或地址运行时计算）。

日志标记 / 关键字：

```text
Broken pipe
```

## reach_probe

`51368` bytes，内核地址立即数 `2` 个。

| addr | off | hits | note |
|---|---|---|---|
| `0xfffffffc7fffffff` | `0x10d8` | 1 |  |
| `0xffffffd400000000` | `0x138c` | 1 |  |

日志标记 / 关键字：

```text
per_cpu/cpu0/trace_pipe_raw 
/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw
perf_event_open (software)
Broken pipe
```

