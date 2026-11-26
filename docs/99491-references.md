> 注：本文件是**参考索引**（写于真机打通前）。最终可用流程与结论见 `docs/99491-solution.md`。

# 99491 参考实现与恢复记录

## 上游参考
- 5.15 原始端口: https://github.com/woshigenm/CVE-2026-99491 （GPL-2.0-only）
- 6.18.21 real_cred 链: https://github.com/Yunnijian/CVE-2026-99491 （本仓库 plant/99491 的基座，GPL-2.0-only）
- XRING O1 家族成功实现: https://github.com/ChaYeWuu/XRING-CVE-2026-99491
  - `docs/02-exploit-chain.md`（P0–P6 全流程、结构偏移、固定词写原语、caps/AVC 配方）
  - `docs/05-pitfalls.md`（evbit 不含 EV_SYN、h_list/grab 不可碰、每写一次重建 UAF、HID_GENERIC 描述符要求等）
- XRING 同族 prague 版: https://github.com/ChaYeWuu/prague-CVE-2026-99491

## 本机（lhasa 2608BPX34C）关键真机结论
- 补丁判定: kallsyms 无 `wacom_report_touch_mute`；98499 OOB 读可达 → 未修补。
- KASLR: 98499 ToolSerial OOB 读稳定；slide 与 kallsyms 双源一致。
- UAF: wacom sibling touch_input 悬垂可复现；kmem oracle 回收命中（depth 64~448）。
- 写原语: XRING/5.15 式 fixed-word 直写在 lhasa 6.18.21 上真机验证通过
  （`TRIGGER_PROBE_OK`: EV_SW 词写 `selinux_state-1` 使 enforcing 1→0）。
- 待完成: tracefs cred 泄漏 → euid/caps 固定词写入 → AVC permissive 窗口 →
  ksud late-load 加载 KernelSU → 恢复 Enforcing → 冷启动复测。

## 本仓库文件恢复记录（2026-11-25）
DSH 文件沙箱在重启后导致少数旧 inode 不可读（`plant/99491/exp.c`、
`plant/99491/README.md`、`build/99491/exp`）。已从会话日志重放恢复：
- `plant/99491/exp_direct.c` = exp.c 全量恢复 + 触发落点修正（sel-1），编译/self-test 通过
- `plant/99491/README_recovered.md` = README.md 全量恢复（16 次编辑重放）
- 交付时在干净 worktree 中把二者归位为 `exp.c` / `README.md`。
