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
| 原件里的日志锚点仍存在 | 硬性 | Java 侧按字符串判定：`必需项全部通过`、`slide=`、`listening` 等 |
| `lhasa_profile` 登记的内核目标常量仍在 | 硬性 | 地址变了利用就打在错的地方 |
| 体积在原件 0.5x~3x 之间 | 硬性 | 体积突变通常说明编译选项不对，不是等价物 |
| 字符串增删、内核立即数增删 | 提示 | 新增串要人工过目，防止意外引入新行为 |

跑法：

```sh
python3 tools/equiv.py check pc98260-su /path/to/rebuild   # 单个
python3 tools/equiv.py check-dir <编译产物目录>              # CI 用这个
```

## 闸 2：运行时行为（设备上）

在已适配的 6.18.21 内核上跑同名程序，比较：

- 退出码
- stdout 逐行 diff（锚点行必须一致；差异只允许出现在数值/耗时上）
- 诊断类（`reach_probe`）：FAIL 行集合必须一致，**不允许新增 FAIL**；
  也不允许把原有 FAIL 说成 OK —— 除非提交信息里写明原因
  （例如 `reach_probe.c` 注释里那条 `attr.size` 误报修正）

## 闸 3：真实入口回归（App）

不要只跑裸二进制。走 `WorkflowEngine` 真实入口：诊断 → 临时 ROOT → KSU 接管，
确认状态机、日志、`onTail` 尾巴都正常。这一步出问题说明锚点抓得不够。

## 闸 4：台账登记（`tools/assets-ledger.json`）

替换的提交必须同时更新台账：

- `origin` 改为 `rebuilt-from-source`
- `sourceDraft` 指向真实源文件
- `sha256` 换成新产物
- `status` 改为 `rebuilt`，`action` 记录「何时、由什么源码、哪些闸通过」

## 替换流程

1. 补全 `plant/<名字>.c`
2. push → compile job 自动 zig 编译 + 跑 `equiv.py check-dir`，红绿即时可看
3. 闸 1 通过后，取出 Artifact 在设备上做闸 2
4. 通过真实入口做闸 3
5. 产物写进 `assets/`，按闸 4 更新台账

## 当前进度

| 资产 | 源码 | 备注 |
|---|---|---|
| `pc98260-su` | `plant/pc98260-su.c` | 结构完整；与原件差异：环境变量名（`PC98260_ROOT_SOCK` vs `PC98260_SOCK`）、usage 文案 |
| `reach_probe` | `plant/reach_probe.c` | 草稿已修正 `attr.size` 误报 |
| `slide_probe` | `plant/slide_probe.c` | 需确认 `slide=` 输出格式与原件一致 |
| `perf_slide` | `plant/perf_slide.c` | 同上 |
| `uaf_plant_replay` | **无源码** | 主利用，必须先补源码 |

## 回退

每个产物替换都是独立提交，回退只需 `git revert` 那一个提交；原件可从
`assets/` 的提交历史取回，台账里也保留了它的 `sha256` 与 `gitBlobSha1`。
