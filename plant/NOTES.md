# plant 目录说明（部署链路与真机教训）

## 部署链路

1. 改 `plant/*.c`
2. 提交信息里带 `[publish]` 推送 → `plant` 工作流的 **publish** job 会：
   - 用 zig 交叉编译四个探针（aarch64-linux-musl，`-O2 -static -s`）
   - 把**当前** assets 的指纹归档到 `plant/equiv/`（作为严格模式基线）
   - 用新产物覆盖 `app/src/main/assets/`
   - 同步 `tools/assets-ledger.json`（origin/status/sha256/size/blob）
   - 推一个带 `[apk] [release]` 的提交
3. **注意**：`GITHUB_TOKEN` 推送的提交不会触发其它工作流（GitHub 防递归规则）。
   所以 publish 之后还要再推一个自己的提交（带 `[release]`）才会真正出包。
4. 装包后可用 `tools/verify_apk_assets.sh` 在设备上自证 APK 里是哪几个二进制。

## 真机踩过的坑（2026-11-22）

| 现象 | 真因 |
|---|---|
| `perf_event_open` 返回 `errno=13 EACCES` | SELinux 只挡**硬件 PMU**；软件事件是允许的（同一调用改成 SOFTWARE 后返回的是 `errno=7 E2BIG`，说明权限通了） |
| `errno=7 E2BIG` | `attr.size` 用了 `sizeof(struct perf_event_attr)`，超出内核可接受尺寸；应使用 `PERF_ATTR_SIZE_VER5` |
| `perf_slide` 在真机上挂住不动 | 采样循环没有上限；外层必须用 `timeout` 包（App 侧已加 8 秒） |
| `slide_probe` 抓到 0 条 `kmem_cache_alloc` | 事件顺序错了：必须**先开 trace 再 `timer_create`**，否则目标分配发生在观测窗口之前 |
| `/proc/kallsyms` 读不到（shell） | 该 ROM 直接 `Permission denied`，不是显示 0；不要指望 kallsyms |
| `kprobe_events` 写不进去 | 对 shell 是 `Device or resource busy`，kprobe 路线走不通 |
| `--duration 1` 几乎采不到样本 | 调用方按**秒**传参，实现按毫秒写就是 1 毫秒 |

## 语义约定（别改错）

- `perf_slide --duration N`：**秒**，实现里夹在 1..8。
- `perf_slide` 输出的 `slide=`：`泄漏 ip − profile 链接期地址` 的差值，2MB 对齐，
  能通过 `KernelSupport.isSlideValid()` 的两条判据。
- `slide_probe` 的 `hits`：`kmem_cache_alloc` 行里出现 `posix_timers_cache` 或
  `bytes_req=384` 的次数；`lines` 只统计 `kmem_cache_*` 行。
- `reach_probe` 有失败时退出码是 **2**（原件行为），不是 1。
