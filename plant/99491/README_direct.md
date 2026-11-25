# plant/99491/README_direct.md — DIRECT 固定词引擎（cred/root 阶段）

> 临时权威说明文件（工作区沙箱故障后 `README.md`/`exp.c` 不可读；本文件与
> `exp_direct.c` 一起由 Lead 在干净 worktree 归位）。目标链依据：
> `_xring/02-exploit-chain.md`、`_xring/05-pitfalls.md`、
> `_99491-upstream/upstream/{poc.c,exp.c,exp.md}`（5.15 参考，含 tracefs cred 泄漏）。

## 1. 定位

`exp_direct.c` 保留原 real_cred/fake-handle 链全部代码，并新增 `CVE99491_ENGINE=direct`
（XRING O1 家族 6.18.21 已验证的 5.15 式固定词直写）收尾阶段：

- **不再需要** host anchor / outq / uinput 载体 / fake handle；
- 每次写 = 一次独立 UAF：touch+pad 对 → 销毁 touch → skb 回收 → pad MUTE 报告让
  `input_event_dispose()` 把 **一个固定 8 字节 input_value 词** 追加到 `vals` 目标；
- 支持两种词：
  - `DIRECT_WORD_V1` = `{EV_SW, SW_MUTE_DEVICE, 1}` = `05 00 0e 00 01 00 00 00`
    （fake dev：`evbit=0x20`、`swbit=0x4000`、`sw=0`、`num_vals=0`、`max_vals=0x1000`、`inhibited=0`）；
  - `DIRECT_WORD_ZERO` = 8 个零字节（fake dev：`evbit=0x21`(含 EV_SYN)、`swbit=0`，
    EV_SW 被 swbit 丢弃，`input_sync()` 的 SYN_REPORT 追加零词）。
- **evbit 绝不带 EV_SYN 的开关词路径**：否则会进 `input_pass_values()` 遍历假 `h_list` 直接 panic
  （XRING pitfall 1.1）。零词路径是唯一带 EV_SYN 的例外，且 `swbit=0` 保证 EV_SW 被丢。
- 每个词写都必须**重建 UAF+重 spray+drain**（pitfall 1.2/1.3；同一假设备第二次上报拿不到词）。
- direct 引擎一次运行内做**多次 UAF**；只在运行开始时写一次 `PARKED` 标记（不做每步 park），
  失败时打印 `PARKED` 退出码 1，成功时只提示“重启后再来”（因为本 boot slab 已脏）。

## 2. 新增函数（exp_direct.c）

| 函数 | 作用 |
|---|---|
| `build_direct_payload()` | 两种固定词的 fake input_dev 垫片 |
| `direct_uaf_write(target, mode, spray_n, spread_ms)` | 一次完整 UAF 写入（建对→销毁→回收 spray→pad 报告→清理/drain） |
| `direct_cred_leak()` | 6.18 tracefs cred 泄漏：`trace_prepare()` + `spawn_wait_child()` + `trace_cred_ptr()`（`bytes_req=0xb8`，`cred_site_low21=0x6d1b4`） |
| `direct_euid_oracle()` | V1 词写 `cred+0x12` → `cred+0x18` euid=0，pipe 读 `geteuid()` 判定，未命中换下一个候选/重试 |
| `direct_enforce_window()` | permissive 窗口开/收：V1 词写 `selinux_state-1` / `selinux_state-2` |
| `direct_resolve_ksud()` | 解析 ksud loader（env/`--ksud`/profile/`/data/local/tmp/ksud`/`/data/adb/ksud`） |
| `direct_read_module_live()` | 轮询 `/proc/modules` 的 `kernelsu ... Live` |
| `run_direct_cred()` / `run_direct_root()` | 两个新阶段入口 |
| `wait_child_main()` 新命令 | `'F'` → 回报 `setfsuid(-1)`（不改 cred）；`'K'` → 子进程原地 exec `late-load` |

## 3. CLI 与阶段

```sh
./exp --stage=cred --profile ... --workdir ...    # 只做泄漏+euid oracle
./exp --stage=root --profile ... --workdir ...    # cred+fsuid0+caps+permissive+ksud late-load+su 验收
./exp --stage=root --no-ksu ...                   # 停在窗口前（会恢 Enforcing）
CVE99491_ENGINE=direct  # 当前仅 cred/root 阶段使用；full 仍是旧 real_cred 链
```

- `cred`：`[+] cred leak: child=… cred=0x… (N bytes)` → `[*] euid try …` →
  `[+] cred cand=0x… euid=0 (uaf_writes=…)` → `CRED_ORACLE_OK`；退出 0。
- `root`：上面 + `[+] fsuid=0` + `[+] caps bit16(CAP_SYS_MODULE)` +
  `[!] permissive window opened at selinux_state-1 (fallback path; …)` + `MODULE_LOADED` +
  `[f] module_live=1 enforce=1` + `[f] su_check=…`；`--no-ksu` 时停在窗口并恢复 Enforcing。
- 失败一律 `PARKED` + 退出 1；任何阶段结束后**必须重启**再跑下一次 fire run。
- 新标记：`[p] engine=direct`、`[+] cred cand=… euid=0`、`CRED_ORACLE_OK`、
  `[+] fsuid=0`、`[+] caps bit16(CAP_SYS_MODULE)`、`[!] permissive window …`；
  `MODULE_LOADED` / `[f] module_live=1 enforce=1` / `[f] su_check=…` / `PARKED` 沿用原契约。

## 4. 关键实现选择（与 5.15 参考的差异/理由）

1. **euid oracle 用 `cred+0x12` 的 V1 词**（而非 5.15 的 `cred+0x14` V0 词）：
   V0 词要求 fake dev 的 `sw` 位预置 1（`input_dev+0x1c0`），该偏移目前不在 profile
   schema 里；V1 词 `05 00 0e 00 01 00 00 00` 落在 `cred+0x12` 时
   `sgid(+0x14)=0x0001000e`、`euid(+0x18)=0`，观测目标一致（uid 保持 2000）。
   后续若需要干净的 V0 词，给 schema 加可选 `input_dev_sw_off`（默认 0x1c0）即可。
2. **fsuid/fsgid 置零用零词**（`cred+0x20`）：不需要 sw 预置；`'F'` 命令回读验证。
3. **permissive 先走已真机验证的 `selinux_state-1` V1 词**（fallback，代码注释已标风险：
   会在 `selinux_state` 前一字节写 0x05、policycap 区清零；5.15 exp.md 记录 `selinux_state-6`
   的 8B 词会破坏 `sel_netport_hash` —— 我们只写 1 字节前缀且随后重启，但 **AVC 节点方案
   （tracefs 抓 72B `avc_node` → 写 `node+0x1c` bit0）尚未标定**，等 Lead 给
   `selinux_avc` 符号地址/分配点后可切换）。
4. **还原词**用 V1 词写 `selinux_state-2`：`selinux_state.enforcing` 字节变成 `0x0e`（非零
   = Enforcing），无需另一套词。
5. `ksu late-load` 由**已提权的子进程原地 exec**（同 pid/cred，走 `CVE99491_KSU_LIB`）；
   `su -c id` 验收由 uid-2000 父进程执行（子进程已 uid0，会踩 KSU `setresuid` 钩子问题），
   所以 `late-load` 里加了 `CVE99491_SKIP_SU_CHECK=1` 开关。
6. 原 KASLR 运行时校验在恢复版里丢了 `+slide`（`worker` vs 链接期 `[stext,etext)` 必然误判），
   已修回 `[stext+slide, etext+slide)`。

## 5. 构建 / 自检（沙箱故障后路径）

```sh
bash plant/99491/build.sh --self-test --src plant/99491/exp_direct.c \
  --out /root/workspace/_99491-calib/out
# 期望：gen_profile OK → 编译 exp_direct.c → ELF aarch64 static stripped →
#       --self-test 输出 SELF_TEST_OK（profile/KMI/backend/ksud）
# --help 应包含 leak|oracle|write|selinux|trigger|cred|root|full 阶段说明
```
（`--src` 是本轮给 build.sh 新增的参数；沙箱故障恢复期必须显式指定 `exp_direct.c`，
否则 build.sh 在 `exp.c` 可读时会优先编旧文件。）

## 6. 已知风险 / 下一步

- 每次 UAF 写入约 0.5–1s（含建对/等待/回收/spray/drain），cred oracle 最多 ~4 写/候选；
  UAF 未命中可能没有写效果（脚本按标记判定，不盲目重试整链）。
- `selinux_state-1` 窗口期间系统短暂 permissive（会立刻载模块并恢复；失败则重启恢复）。
- `root` 阶段首次验证要点：ksud loader 是否存在于测试 boot（无 KSU 时需推 assets ksud 或
  传 `--ksud`）；`su` 二进制是否在 `/system/bin/su` 或 `/data/adb/ksu/bin/su`；模块 Live 后
  KSU 注入策略是否需要厂商 HAL 修复（本引擎未做，失败可后续加）。
- 待 Lead 标定后可切换：AVC 节点开窗（`selinux_avc`、avc_node 分配点）、`input_dev_sw_off`
  （干净 V0 词）、KSU manager 拉起/GRANT_ROOT（若 `su -c id` 需要）。
