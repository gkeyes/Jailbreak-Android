# P0 补丁：按失败状态区分重试

分支：`fix/p0-clean-boot-retry`

## 为什么

`WorkflowEngine.containsRetryMarker()` 把两种结构完全不同的失败当成同一类：

```java
return tail.contains("holding zombie")     // 节点已挂树，悬空节点存在
    || tail.contains("leak failed")        // 泄漏阶段失败，尚未 plant
    || tail.contains("[selinux] attempt 2/");
```

`leak failed` 时堆是干净的，同一次开机重试安全。`holding zombie` 时 timerqueue 节点仍挂在存活任务的 `posix_cputimers` 红黑树里，第二次跑 payload 会让 `release_task()` 对同一批已释放对象再做一次 `rb_erase`——结果是内核故障，不是返回错误。

原实现让这两种状态都进入第 2、3 次尝试，等于用稳定性换「多试两次」。

## 改了什么

### 1. 新增 `BootGuard`

`classify()` 返回四种结果，`ABORT_BOOT` 在 `SUCCESS` 之前判定：

| 输出标记 | Outcome | 处置 |
|---|---|---|
| `holding zombie` / panic 特征 | `ABORT_BOOT` | 立即终止本次开机，写失败标记 |
| `[child-cred] uid=0` / `[cred] rooted` | `SUCCESS` | 进入验证 |
| `leak failed` / `[selinux] attempt ` | `RETRY_SAFE` | 同开机快速重试 |

同时把 `holding pages` 与 `[selinux] already permissive` 从成功判据里移除：前者是中间状态，后者只说明 SELinux 阶段完成、uid 仍是 2000。

### 2. `stopPayload()` 改用进程组信号

`/proc` 是 `hidepid=invisible`，`pkill -f` / `killall` 的非 root 扫描看不到 payload，旧实例可能存活并与新实例抢 `mmap_lock`。改为启动时记录 `$$`（`setsid` 下即 pgid），停止时 `kill -TERM/-KILL -pgid`，顺带给 `payloadProcessCount()` 一个不依赖 `ps` 的探针。

### 3. 未匹配内核直接阻断

原实现只打一句「风险自负」就继续。带错 offsets 执行 `rb_erase` 的后果是 panic，会白白烧掉一次开机机会。现在 `recordFailedBoot()` 后抛出。

## 附带改动

`AssetDeployer.RUNTIME_ASSETS` 移除 `ksud`。它在第 6 步已单独 `stage("ksud")`，原实现每次点按从 Shizuku 管道重传两遍约 5 MB，且其中一遍落在提权前的竞态窗口。

## 如何应用

```bash
git checkout fix/p0-clean-boot-retry
patch -p1 --forward < docs/patch/p0-workflow-engine.diff
```

`git apply` 也可以用，需要时加 `--recount`（补丁里的行号是近似值，`patch` 会按上下文自行定位）。

应用后可选清理：`WorkflowEngine` 里 `RUNNING_PAYLOAD`、`java.util.regex.Matcher`、`java.util.regex.Pattern` 已无引用，删掉可消掉编译告警。

## 未包含（P1，另开分支）

- slide 每开机缓存（`perf_slide` 重试时省 1–3 秒）
- 测量与空闲等待的顺序调整（测地址 → 等空闲 → 提权）
- 轮询节流 / 常驻 shell（每次尝试约 200 次 `Shizuku.newProcess`）
- 部署与空闲等待的 `join(8000L)` 竞态
- `ksud` 增量部署校验
