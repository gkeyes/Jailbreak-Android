# 真机调试与重启约定

这条链上「重启」不是故障，是设计的一部分：UAF 失败后内核堆已经脏了，
在同一次开机里重试只会让 `release_task()` 二次释放已摘除的节点，直接 panic。
所以**该重启的时候必须重启，不该重启的时候一次都别多**。

## 什么时候必须重启

| 现象 | 原因 | 处理 |
|---|---|---|
| payload 日志出现 `holding zombie` / `Kernel panic` / `BUG: unable to handle` | 定时器节点已挂进活任务的 rbtree，堆已污染 | 立即停手，重启 |
| 提权失败且 `getenforce` 仍是 `Enforcing` | 内核状态被写坏，重试只会加剧 | 重启后再试 |
| `KernelSU late-load` 之后 `su -c id` 无响应 | 内核模块加载把内核卡住 | 重启，且本次不再试 KSU |
| 采样器/探针超过 timeout 仍未退出 | root 进程常驻，会把 `system_server` 拖进 soft lockup | 先 `kill -9`，仍异常则重启 |

反过来，**这些情况不要重启**：
- `getenforce` 已是 `Permissive` 且失败停在 cred 阶段 —— 可直接重试（`WorkflowEngine`
  会读 `.lhasa_failed_boot` 判断）；
- 只是探针返回 FAIL（例如 `perf_event_open` 的 E2BIG 误报）—— 那是环境信息，不是污染。

## 禁止：在提权后的脏内核上再次连接 rootd

**2026-11-22 第二次重启就是这条踩出来的。** 为了做闸 2 比对，用 root 跑了
`pc98260-su -c "id"`（原件与重建件各一次），设备随即重启。

原因：`rootd` 不是普通服务，它是 `uaf_plant_replay` 在**已经被污染的堆**上起起来的
临时 root 通道。再去连它发命令，等于复用那份不稳定的内核状态，panic 是预期结果之一。

规则：
- 闸 2 里的 `pc98260-su` 只能对**自建的假 rootd**（独立 socket、独立进程）测协议，
  不许连真 rootd；
- 真 rootd 只在同一次开机的提权流程内部使用，流程结束就当它已经不能碰；
- 任何「顺手试一下」的 root 操作，都要先按下面的约定确认。

## 重启前（30 秒，别省）

1. App 里点「导出日志」→ `Download/lhasa26/`（已过 `LogRedactor` 脱敏）；
2. 记下 `cat /data/local/tmp/.lhasa_stage`：它会告诉你上次停在哪一步；
3. 需要现场证据时顺手 `cp /data/local/tmp/uaf_replay.log /sdcard/Download/`。

## 重启后

1. **Shizuku 不会自启**：DSH → 设置 → 手机 → 重开 Shizuku；
2. **临时 ROOT 已失效**：需要重新点「一键临时 ROOT」；
3. 看 App 日志第一屏的 `[上次] …` 一行 —— 面包屑会说清上次被哪一步带走；
4. `.lhasa_failed_boot` 里如果记的是本次开机，App 会拒绝再跑并提示原因。

## 给操作者的约定（我这边）

每次要动内核之前，我会先说明三件事：
1. 现在要跑哪一步（诊断 / 测 slide / 提权 / KSU late-load）；
2. 这一步失败会怎样（例如「失败且 SELinux 仍 Enforcing 时需要重启」）；
3. 日志导出了没有。

不会做的事：不带 `timeout` 跑采样器；失败后在同一次开机里连点；自动 late-load 内核模块
（已改成手动 + 二次确认）；以及在提权后的脏内核上连真 rootd。

## 已发生过的实例

1. 2026-11-22 早：人工在 root 下跑 `perf_slide --period 1000 --duration 300`，
   120 秒未返回，随后设备重启 → 促成 `BootGuard.withTimeout` 与 KSU 接管改手动。
2. 2026-11-22 晚：闸 2 比对时用 root 跑 `pc98260-su -c id` 连真 rootd，设备重启
   → 促成上面那条「闸 2 只能用假 rootd」的规则。
