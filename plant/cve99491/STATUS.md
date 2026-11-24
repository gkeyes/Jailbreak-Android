# cve99491 状态

截至 2026-11-24：

| 组件 | 状态 |
|---|---|
| `site_probe` | ✅ 可用（测 cred / blob 的 tracefs 分配站点） |
| `c99491_load` | ✅ 可用（符号表绑定 + `finit_module`；含窗口内策略重载） |
| `tools/gen_ksu_syms.js` | ✅ 225/225 符号命中 |
| 装载模块 | ✅ 成功 2 次（`finit_module rc=0`、模块 Live、`su` 可用） |
| 长期稳定 | ❌ 未达成（开 permissive 必然破坏 `selinux_state`，1–5 分钟内重启） |

## 结论

本链路**可用于单次装载**（临时 root），**不可长期运行**。

根本原因：开 permissive 只能写 `selinux_state` 内存（合法 `setenforce` 在
Enforcing 下被策略拒绝），而写它会清掉 `initialized` 与 `policycap`；本机
该结构体布局未知（`.bss`，镜像中不可读；BTF 被裁剪），写原语也无法精确恢复。

## 下一步（推荐）

移植上游 `real_cred` 模式的 **oracle 验证回收** 与 **PARKED** 保护：
`real_cred` 走 `setcon` 切域，不需要关 SELinux，从根上避免本问题。

详见 `docs/cve99491-lhasa-lessons.md`。
