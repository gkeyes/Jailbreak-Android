# payload 源码化：等价性的定义与替换流程

目标：`app/src/main/assets/` 里的原生件全部由本仓库的 C 源码重建，
不再依赖不可追溯的预编译产物。

**「等价」不等于字节相同。** 换编译器就换字节，这不代表功能变了；
真正会坏的是语义骨架。所以等价性拆成四道闸，前一道不过就不往下走。

## 闸 1：静态锚点（`tools/equiv.py`，CI 自动跑）

参照物就是 `app/src/main/assets/<名字>` 里的**原件**——它一直在 git 历史里，
不需要另外提交「基线文件」。

| 检查 | 性质 | 理由 |
|---|---|---|
| ELF / 64 位 / aarch64 | 硬性 | 目标机是 arm64 Android |
| 原件里的日志锚点仍存在 | 硬性 | Java 侧按字符串判定 |
| `lhasa_profile` 登记的内核目标常量仍在 | 硬性 | 地址变了利用就打在错的地方 |
| 体积在原件 0.5x~3x 之间 | 硬性 | 体积突变通常说明编译选项不对 |
| 字符串增删、内核立即数增删 | 提示 | 新增串要人工过目 |

```sh
python3 tools/equiv.py check pc98260-su /path/to/rebuild   # 单个
python3 tools/equiv.py check-dir <编译产物目录>              # CI 用这个
```

草稿期没有归档基线时是**报告模式**（只列 GAP 不判红）；
某资产归档过 `plant/equiv/<名字>.json` 后自动进入**严格模式**（不过即红）。

## 闸 2：设备行为（`tools/device_verify.sh`）

在已适配的 6.18.21 内核上，原件与重建物**成对执行**再比输出：

```sh
# root shell（Shizuku 提权后或 adb shell su）
mkdir -p /data/local/tmp/plant/{orig,new}
# 原件：从 assets/ 拷；重建物：从 CI Artifact plant-binaries/out 拷
tools/device_verify.sh run /data/local/tmp/plant/orig /data/local/tmp/plant/new
```

脚本固定参数、归一化 pid/字节数/耗时/地址，然后逐行 diff；退出码不一致也算失败。
日志落在 `/data/local/tmp/plant/out/logs/`，差异看 `*.diff`。

判定口径：
- 锚点行（OK/FAIL 行、`[slide]`/`[perf]`/`[stream]` 前缀行）不许增加或消失
- 新增 FAIL 一律视为不等价；把原有 FAIL 变成 OK 必须在提交信息里写明原因
  （例如 `reach_probe.c` 注释里那条 `attr.size` 误报修正）

## 闸 3：真实入口回归（App）

走 `WorkflowEngine` 真实入口：诊断 → 临时 ROOT → KSU 接管，确认状态机、
日志、`onTail` 尾巴都正常。只跑裸二进制不够——入口层还有超时与重试逻辑。

## 闸 4：台账登记（`tools/assets-ledger.json`）

替换的提交必须同时更新台账：`origin` 改为 `rebuilt-from-source`、
`sourceDraft` 指向真实源文件、`sha256` 换成新产物、`status` 改为 `rebuilt`。

## 当前进度

| 资产 | 源码 | 闸 1 | 闸 2 | 闸 3 |
|---|---|---|---|---|
| `pc98260-su` | `plant/pc98260-su.c` | ✅ 0 GAP | 待跑 | 待跑 |
| `reach_probe` | `plant/reach_probe.c` | ✅ 0 GAP | 待跑 | 待跑 |
| `slide_probe` | `plant/slide_probe.c` | ✅ 0 GAP | 待跑 | 待跑 |
| `perf_slide` | `plant/perf_slide.c` | ✅ 0 GAP | 待跑 | 待跑 |
| `uaf_plant_replay` | **无源码（原始目录已丢失）** | — | — | — |

`uaf_plant_replay` 的结论与已知契约（CLI、日志路径、套接字、五个阶段）记在
`tools/assets-ledger.json` 的 `contract` 字段里，供以后做反汇编重建时对照。

## 回退

每个产物替换都是独立提交，回退只需 `git revert` 那一个提交；原件可从
`assets/` 的提交历史取回，台账里也保留了它的 `sha256` 与 `gitBlobSha1`。
