# 等价性验证：现在怎么验

目标：`app/src/main/assets/` 里的原生件都可追溯到源码，且换实现时不悄悄退化。

## 现状（2026-11-22）

| 资产 | 来源 |
|---|---|
| `reach_probe` | 自有 `plant/reach_probe.c` |
| `slide_probe` | 上游 MIT `src/xr98260_slide_probe.c` |
| `pc98260-su` | 上游 MIT `src/pc98260_su.c` |
| `uaf_plant_replay` | 上游 MIT `src/exploit-android-perf.c` |
| `ksud` | KernelSU v3.3.1 `libksud.so`（GPL-3.0） |

上游钉在 `tools/xring.lock.properties`（commit + tarball sha256），
由 `tools/build_xring.sh` 下载校验后编译。

## 闸 1：静态锚点（CI 自动，`tools/equiv.py`）

参照物是 `plant/equiv/<名字>.json` = **首次替换前原件**的指纹（一经归档不覆盖）。
自有源码的产物每次构建都要过：

- ELF / 64 位 / aarch64
- 原件的日志锚点仍存在
- `lhasa_profile` 登记的内核目标常量仍在
- 体积在 0.5x~3x

上游源码构建的产物不过这道闸——它的可信度来自「钉版 tarball + sha256」，
而不是与原件逐字相同（本来就不是同一份实现）。

```sh
python3 tools/equiv.py check-dir <编译产物目录>
python3 tools/equiv.py baseline      # 已存在则 KEEP，重建需 --force
```

## 闸 2：上机跑（**shell 身份**）

**不需要 root。** 整条链的设计前提就是「以 shell 权限泄漏 KASLR，再提权」，
所以测试必须在 shell 身份下做，root 反而掩盖问题。

```sh
# 1. 取产物（两种都行）
#    A. 从 CI 的 plant/out/<名字>.b64 解码
base64 -d <名字>.b64 > /data/local/tmp/<名字> && chmod 755 /data/local/tmp/<名字>
#    B. 从已安装 APK 里抽
unzip -p "$(pm path com.gkeyes.lhasa26 | head -1 | sed 's/^package://')" assets/<名字> > /data/local/tmp/<名字>

# 2. 关键一步：拿 slide（必须能打印 slide=0x…）
timeout 10 /data/local/tmp/slide_probe

# 3. 用拿到的 slide 跑主利用
/data/local/tmp/uaf_plant_replay --slide 0x<上一步的值>
```

判据：
- `slide_probe` 必须输出 `site=0x… slide=0x…`，且 slide 是 2 MiB 对齐
- `uaf_plant_replay` 出现 `[cred] rooted` 或 `[rootd] listening` 才算成功
- 出现 `holding zombie` 就必须重启，不能在同一次开机重试

`pc98260-su` 的协议比对用 `tools/gate2_pc98260.sh`（只测连接失败与参数解析，
不碰真 rootd——连它会让已污染的堆再次崩溃）。

## 闸 3：App 真实入口

只有验证 `WorkflowEngine` 的超时/重试/状态机时才需要装 APK。
装完可先跑 `tools/verify_apk_assets.sh` 自证 APK 里的 assets 与台账一致
（哈希直接读 `tools/assets-ledger.json`，不再硬编码）。

## 闸 4：台账

替换产物必须同步 `tools/assets-ledger.json`：`origin`、`sourceDraft`、`license`、
`sha256`、`size`。`tools/check_assets.py --strict` 是 CI 第一道门。

## 回退

每次替换都是独立提交，`git revert` 即可；原件指纹留在 `plant/equiv/`，
原二进制在 git 历史里。
