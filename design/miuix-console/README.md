# miuix-console（界面模块）

只负责渲染与本地交互（翻页、菜单、确认框），业务动作由宿主
（`com.gkeyes.lhasa26.ConsoleActivity`）通过 `FoldEvent` 执行。

## 确认框归属（重要）

**确认框统一由本模块的 `FoldDialogs` 负责。**

- `FoldConsole.onRequest` 会拦截 `HELP / SETTINGS / CLEAN / SOFT_REBOOT / REBOOT`，
  弹一次 Miuix 玻璃态对话框；用户点“确认”之后才把事件转发给 `onEvent`。
- 因此宿主收到 `SOFT_REBOOT` / `REBOOT` 时**必须直接执行**，不能再弹原生
  `AlertDialog`——否则用户会看到两个风格不同的确认框（2026-11-23 修过一次）。
- `HELP` 完全由本模块消费（`GlassBottomSheet` / `OverlayBottomSheet`），
  宿主侧不要保留帮助分支，那是死代码。

## 帮助文案

帮助内容写在 `FoldOverlays.kt` 的 `FoldDialogs` 里，共六步。
**行为变了就要同步改这里**，否则用户按旧文案操作会困惑：

1. 授权 Shizuku（点主按钮会自动拉起并请求授权）
2. 接口诊断（只读，不改内核状态）
3. 一键临时 ROOT（测 slide → 跑利用 → 起 rootd）
4. 自动接管 KernelSU（late-load 内核模块，最容易触发重启的一步）
5. 软重启 = 重载框架（`stop; start`，zygote 重新拉起，Zygisk/LSPosed 重新注入）
6. 重启后临时 ROOT 失效，需要重跑

## 布局

- 宽度 ≥ 700dp 用左侧导航栏，≥ 872dp 且 `fontScale ≤ 1.35` 用宽版单列。
- 折叠屏展开/闭合会改变 density，`AndroidManifest` 的 `configChanges` 必须覆盖
  `density|screenLayout|screenSize|uiMode|fontScale|locale`，否则 Activity 会重建，
  而宿主 `onDestroy` 里有 `engine.stop()`，会在提权中途把会话掐掉。
