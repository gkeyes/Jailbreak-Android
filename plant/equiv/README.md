# payload 源码化：等价性的定义与替换流程

目标：`app/src/main/assets/` 里的原生件全部由本仓库的 C 源码重建，
不再依赖不可追溯的预编译产物。

**「等价」不等于字节相同。** 换编译器就换字节，这不代表功能变了；
真正会坏的是语义骨架。所以等价性拆成四道闸，前一道不过就不往下走。

## 闸 1：静态锚点（`tools/equiv.py`，CI 自动跑）

| 检查 | 硬性 | 理由 |
|---|---|---|
| ELF / 64 位 / aarch64 | 是 | 目标机是 arm64 Android |
| 基线里的日志锚点仍存在 | 是 | Java 侧按字符串判定：`必需项全部通过`、`slide=`、`listening` 等 |
| `lhasa_profile` 登记的内核目标常量仍在 | 是 | 地址变了利用就打在错的地方 |
| 体积不离基线 0.5x~3x | 提示 | 体积突变通常说明编译选项不对 |
| 字符串增删 | 提示 | 新增串要人工过目，防止意外引入新行为 |

基线由 `tools/equiv.py baseline` 从**现有预编译件**提取，通过 Artifact 交给人工提交到
`plant/equiv/<名字>.json`。基线不进 CI 的写路径——它是「标准答案」，必须可 review。

## 闸 2：运行时行为（设备上）

在已适配的 6.18.21 内核上跑同名程序，比较：

- 退出码
- stdout 的逐行 diff（锚点行必须一致；差异只允许出现在数值/耗时上）
- 诊断类（`reach_probe`）：FAIL 行集合必须一致，**不允许新增 FAIL**；
  也不允许把原有 FAIL 说成 OK —— 除非在提交信息里写明原因（例如 `reach_probe.c`
  里注释的 `attr.size` 修正）

## 闸 3：真实入口回归（App）

不要只跑裸二进制。走 `WorkflowEngine` 的真实入口：诊断 → 临时 ROOT → KSU 接管，
确认状态机、日志、`onTail` 尾巴都正常。这一步出问题说明锚点抓得不够。

## 闸 4：台账登记（`tools/check_assets.json`）

替换的提交必须同时更新 `tools/assets-ledger.json`：

- `origin` 改为 `rebuilt-from-source`
- `sourceDraft` 指向真实源文件
- `sha256` 换成新产物
- `status` 改为 `rebuilt`，`replacements` 里追加 `{date, source, equiv, deviceRun}`

## 替换流程（每个资产走一遍）

1. `workflow_dispatch` 跑 plant.yml 的 **baseline** job，下载 `plant-baselines` Artifact
2. 把 `plant/equiv/<名字>.json` 提交（这是标准答案，第一次建立后不再随便动）
3. 补全 `plant/<名字>.c`（或用已有草稿）
4. push → compile job 自动编译 + 跑 `equiv.py check-dir`
5. 闸 1 通过后，把产物取出来在设备上做闸 2
6. 通过真实入口做闸 3
7. 产物写进 `assets/`，同时按闸 4 更新台账

## 当前进度

| 资产 | 源码 | 闸 1 | 闸 2 | 闸 3 | 备注 |
|---|---|---|---|---|---|
| `pc98260-su` | `plant/pc98260-su.c`（完整） | 待建基线 | 未跑 | 未跑 | 最小，建议第一个替换 |
| `reach_probe` | `plant/reach_probe.c`（完整） | 待建基线 | 未跑 | 未跑 | 草稿已修正 `attr.size` 误报 |
| `slide_probe` | `plant/slide_probe.c`（草稿） | 待建基线 | 未跑 | 未跑 | 需确认 slide 输出格式与原件一致 |
| `perf_slide` | `plant/perf_slide.c`（草稿） | 待建基线 | 未跑 | 未跑 | 同上 |
| `uaf_plant_replay` | **无源码** | — | — | — | 主利用，必须先补源码 |

## 回退

每个产物替换都是独立提交，回退只需 `git revert` 那一个提交 —— 台账里保留了
被替换件的 `sha256` 与 `gitBlobSha1`，可以随时把原件找回来比对。
