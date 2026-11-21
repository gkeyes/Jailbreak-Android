# 18fold 界面模块

控制台、设备、记录和浮层使用 Miuix `0.9.5-beta03`。界面布局以浅色、深色和折叠屏验收图为基准。

| 位置 | 组件 |
| --- | --- |
| 顶栏、设置入口和图标 | `GlassTopAppBar`、`GlassIconButton`、`MiuixIcons.Glass` |
| 手机和折叠屏导航 | `GlassNavigationBar`、`GlassNavigationRail` |
| 设置和维护确认 | `GlassDialog`、`GlassDialogButton` |
| 使用帮助和更多菜单 | `GlassBottomSheet`、`GlassIconDropdownMenu` |
| 正文、按钮和开关 | `Card`、`BasicComponent`、`TextButton`、`Switch` |

浅色使用 Miuix 的浅灰画布 `#F7F7F7`，深色使用纯黑画布 `#000000`。主按钮使用 Miuix 默认蓝，授权和次要操作使用默认次按钮。宽屏按可用窗口宽度显示侧栏，正文根据剩余宽度和字体大小分栏。

## 玻璃采样

正文先铺不透明底色，再通过独立图层录制，供顶栏、底栏和侧栏采样。页面采样范围包括导航和页面内容，供弹窗、底部面板和菜单使用。浮层由 `Scaffold` 的宿主管理，绘制在采样层外。

关闭特效或运行环境无法使用着色器时，顶栏、导航、菜单和浮层切回 Miuix 常规组件，软件窗口也能使用。嵌入 View 的宿主可通过 `setHardwareEffectsEnabled(false)` 选择软件位图绘制。

[上游迁移指南](https://github.com/YuKongA/Mishka/blob/main/docs/miuix-glass-migration.md) · [Miuix beta03 发布说明](https://github.com/compose-miuix-ui/miuix/releases/tag/v0.9.5-beta03)

## 接口

Compose 从 `FoldConsole(state, onEvent)` 进入。View 宿主使用 `FoldConsoleView`，并提供 AndroidX 生命周期及保存状态所有者。为 View 设置稳定 ID 可以恢复导航状态。

`FoldUiState` 由宿主提供。控制台显示当前授权、会话进度和宿主提供的操作可用性。维护操作经用户确认后发出原有 `FoldEvent`，取消仅关闭弹窗。设置由宿主回传，记录页读取实际传入的日志并支持文字选取。

## 独立构建

需要 JDK 17、Android SDK Platform 37.2、Gradle 9.9.1、AGP 9.4.1、Kotlin Compose 插件 2.4.21 和 Compose 1.13.0-rc01。最低运行版本为 Android 17（API 37）。在本目录构建界面库：

```sh
./gradlew :ui:assembleDebug :ui:assembleRelease
```

产物位于 `ui/build/outputs/aar/`。
