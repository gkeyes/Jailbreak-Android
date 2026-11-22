# plant 目录说明（部署链路与真机教训）

## 两条分发通道

**A. 直接上机测（推荐，秒级）**
publish 会把产物写成 `plant/out/<名字>.b64`（单行 base64）。设备上：

```sh
base64 -d /sdcard/Download/perf_slide.b64 > /data/local/tmp/perf_slide
chmod 755 /data/local/tmp/perf_slide
timeout 10 /data/local/tmp/perf_slide --duration 1
```

不需要打包 APK。**测探针功能就走这条**。

**B. 装 APK（只在验证 App 调度时才需要）**
提交信息带 `[release]` → `build-apk` 产出带签名的 release 包并挂到 Releases。
只有要验 `WorkflowEngine` 的超时/重试/状态机时才需要。

## publish 做了什么

提交信息带 `[publish]` 推送 → `plant` 工作流：

1. zig 交叉编译四个探针（aarch64-linux-musl，`-O2 -static -s`）
2. 把产物写成 `plant/out/*.b64`（供 A 通道）
3. **从历史取回原件**（`git show 8c7de444^:app/src/main/assets/<名字>`）并归档到 `plant/equiv/`
4. 再用新产物覆盖 `app/src/main/assets/`
5. 同步 `tools/assets-ledger.json`

注意：`GITHUB_TOKEN` 推送不会触发其它工作流（GitHub 防递归），所以 publish 之后
还要再推一个自己的提交（带 `[release]`）才会出包。

## 基线语义

`plant/equiv/<名字>.json` = **首次替换前原件**的指纹，一经归档不再覆盖
（`equiv.py baseline` 遇到已存在文件会 `KEEP`，重建需 `--force`）。

## 真机踩过的坑（2026-11-22）

| 现象 | 真因 |
|---|---|
| `perf_event_open` 返回 `errno=13 EACCES` | SELinux 只挡**硬件 PMU**；同一调用改成 SOFTWARE 返回 `errno=7 E2BIG`，说明权限通了 |
| `errno=7 E2BIG` | `attr.size` 用了 `sizeof(struct perf_event_attr)`；应用 `PERF_ATTR_SIZE_VER5` |
| `perf_slide` 挂住不动 | 采样循环无上限；外层必须 `timeout`（App 侧已加 8 秒） |
| `perf_slide --duration 1` 采不到样本 | 调用方按**秒**传参，实现按毫秒写等于 1 毫秒 |
| `slide_probe` 抓到 0 条 `kmem_cache_alloc` | 必须**先开 trace 再 `timer_create`** |
| `/proc/kallsyms` 读不到（shell） | 该 ROM 直接 `Permission denied`，不是显示 0 |
| `kprobe_events` 写不进去 | 对 shell 是 `Device or resource busy` |

## 语义约定

- `perf_slide --duration N`：**秒**，实现里夹在 1..8。
- `perf_slide` 的 `slide=`：泄漏 ip − profile 链接期地址的差值，2MB 对齐，
  能过 `KernelSupport.isSlideValid()`。
- `slide_probe` 的 `hits`：`kmem_cache_alloc` 行里出现 `posix_timers_cache` 或
  `bytes_req=384` 的次数；`lines` 只统计 `kmem_cache_*` 行。
- `reach_probe` 有失败时退出码是 **2**。
