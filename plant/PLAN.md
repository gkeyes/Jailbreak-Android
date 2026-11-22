# 无黑盒：验收标准与现状

目标：仓库里不再存在不可读的二进制，一切构建都从源码开始。

## 四条验收标准

1. `app/src/main/assets/` 下不再有任何 ELF。五个 payload 全部由 `plant/*.c` 在 CI 里编译产出。
2. `plant/` 自包含：只需 zig + 仓库内容即可构建，不依赖外部 apk 或已编译件。
3. `ksud` 由上游开源代码构建，或从流程中移除（不得以不透明文件形式入库）。
4. `ShizukuExecutor` 改用公开 `UserService` 接口，去掉对私有 `newProcess` 的反射。

`plant-build.yml` 已经在守护第 1 条：jobs 失败列表里列出尚未有源码的资产。

## 现状（2026-11-22）

| 资产 | 大小 | 源码 | 备注 |
|---|---|---|---|
| `uaf_plant_replay` | 88 KB | 无 | 主利用 |
| `perf_slide` | 31 KB | 无 | perf 测 slide |
| `slide_probe` | 44 KB | 无 | kprobe 后备 |
| `reach_probe` | 51 KB | 无 | 接口诊断 |
| `pc98260-su` | 28 KB | 无 | rootd 客户端 |
| `ksud` | 4.9 MB | 无 | 上游 KernelSU 用户态 |

## 常量：lhasa 实际值 vs 内置兑底值

`plant/analysis-report.md` 里 `uaf_plant_replay` 偏移 `0x155a8` 起是内置 profile 表。
对照 `lhasa_profile.txt` 三行可确认：内置表对应的是 `g805aa6adea19`（18 Fold 4.0.26），
**不是 lhasa 的 `g284297031c53`**。

| 条目 | lhasa `g284297031c53` | 内置表 `g805aa6adea19` | 相同？ |
|---|---|---|---|
| timer | `0xffffffc08042aa68` | `0xffffffc0803a726c` | 否 |
| cred | `0xffffffc08026c02c` | `0xffffffc08026d1b4` | 否 |
| task_site | `0xffffffc0801f2ec8` | `0xffffffc0801f006c` | 否 |
| selinux | `0xffffffc082959630` | `0xffffffc082959630` | 是 |
| userns | `0xffffffc0826d10d8` | `0xffffffc0826d10d8` | 是 |
| rootuser | `0xffffffc0826d1388` | `0xffffffc0826d1388` | 是 |
| groups | `0xffffffc0826d2a48` | `0xffffffc0826d2a48` | 是 |
| ucounts | `0xffffffc0826d2f08` | `0xffffffc0826d2f08` | 是 |
| task_bytes | `0x1680` | `0x1680` | 是 |
| stext | `0xffffffc080010000` | — | — |
| etext | `0xffffffc081360000` | — | — |

结论：payload 靠运行时解析 `lhasa_profile.txt` 的 `release=` 行取地址，内置表只是兑底。
资产缺失或 `uname -r` 不严格匹配时，它会静默地用 18 Fold 的地址写内核，而不是报错。
重写时这一点必须改成“查不到就拒绝”。

## 日志契约（重写时保持一致）

`BootGuard.classify()` 依赖这三个标记，换实现不得改字符串：

```text
[selinux] attempt %d/6
[cred] plant attempt %d/8
[uaf] missed page; holding zombie
[task] leak failed
[cred] child=%d holding pages
[child-cred] uid=0
[cred] rooted via cred+8/+16 fixups
[rootd] listening at %s pid=%d
```

完整列表见 `analysis-report.md`。

## 待测项

以下两个常量不在 profile 表里，内置表也没直接给，需要在 lhasa 上实测：

1. `task->cred` 偏移（BRM 是 `0x908`，lhasa 同属 6.18.21 线，极可能相同）。
2. `k_itimer` 尺寸与 `cpu_timer.node` 偏移（BRM 是 `0x180` / `+0xe0`）。

两者都可在拿到 shell 后用退化探针量：先 `perf_slide` 定 slide，再用 tracefs
`kmem_cache_alloc` 探针读 `posix_timers` 的对象地址，对象内 `node` 与 `it` 的相对位置由
`timerqueue` 操作点的反汇编给出。

## 顺带发现

`uaf_plant_replay` 的流程里 `[cfg] ... site=%#lx` 说明它接受 `--site` 参数，
即允许直接给一个 kprobe 地址而不必先算 slide——这对排查阶段错位有用。
