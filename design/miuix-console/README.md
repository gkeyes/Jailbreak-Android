# 18fold越狱 · 原生界面设计与实现

本目录是独立的 Android 界面库，产物是 AAR。控制台、设备和记录沿用已认可的三页信息架构。页面壳、按钮、列表和弹窗使用 Miuix；状态卡、玻璃按钮的光泽、导航胶囊及折射层为 18fold 单独设计。当前应用发布入口仍在仓库根目录的 `app` 模块，两套构建彼此独立。

## 页面和信息层级

| 页面 | 第一眼展示 | 交互与反馈 |
| --- | --- | --- |
| 控制台 | 状态标题、临时 ROOT 状态、一个主操作 | 已有宿主决定主操作文案和可用性。Shizuku 名称、状态和授权入口始终有独立位置。会话进度出现时显示步骤和用时。点「最近记录」进入记录页。 |
| 设备 | 设备代号、系统版本、内核版本、适配状态 | 诊断与信息放在一起。清理、软重启、重启集中在维护区，确认弹窗说明影响。取消关闭弹窗，确认才向宿主发出事件。 |
| 记录 | 本次会话和导出入口 | 空记录有明确空态。有内容时使用可选择的等宽文字，长行随宽度换行。用户在三页间切换后可继续在原来的滚动位置阅读。 |
| 设置 | 屏幕常亮、跟随系统的外观、宿主传入的版本 | 保持屏幕常亮使用 Miuix Switch。开关显示宿主回传值。没有版本号时隐藏这一行。 |

## 材质规范

- **页面底色**在浅色模式使用 `#FFFFFF`，夜间使用 `#000000`。主色采用深青绿 `#096250` 和夜间薄荷绿 `#82D8B9`。状态、错误和完成均保留文字表达。
- **状态卡**采用 26dp 圆角和完整轮廓。右侧局部折面由背面、厚边和迎光面组成，呼应 18 图标的折带。装饰绘于内容下层，文字、按钮和手势可独立工作。
- **按钮**用 Miuix TextButton 承接点击、禁用和无障碍操作；触点横坐标驱动上沿的局部高光。主按钮和次按钮分别使用深青或薄荷、冷白或深灰材质。正文和日志区域保留纯色。
- **导航**在三个目的地之间共用一个凸面选中胶囊。拖动位置直接跟手，松手从最后一次触点的位置启动弹簧；取消拖动回到原页。高光和内侧阴影有变化，外围轮廓连续。
- **绘制策略**仅导航区域对页面图层做实时折射，着色器、形状及笔刷按绘制尺寸缓存。Android 17 硬件加速窗口启用 GPU 折射；软件绘制环境使用同形状的渐变玻璃。宿主在硬件窗口中导出软件位图时，可在构建该画面前传入 `hardwareEffectsEnabled = false`，View 入口对应 `setHardwareEffectsEnabled(false)`。此设置同时关闭导航折射和 Miuix 的着色器圆角。静止时不运行独立的光效动画循环。尚未给这些设计赋予未经实测的省电或帧率指标。

## 折叠屏和可访问性

| 条件 | 版式行为 |
| --- | --- |
| 可用窗口宽度小于 700dp | 底部悬浮导航，正文单列；内容末尾为导航留出滑动空间。 |
| 可用窗口宽度至少 700dp | 左侧悬浮导航。正文实际可用宽度达到 720dp，且系统字号倍率不超过 1.35 时，控制台和设备页使用两栏。记录保持单一阅读列。 |
| 信息列宽度小于 300dp，或字号倍率至少 1.3 | 系统参数的值排到标签下面，Shizuku 按钮独占一行。 |
| 返回、换页与窗口尺寸变化 | 当前页和各页滚动位置可恢复。次级页返回控制台，位于控制台时由宿主管理系统返回。导航同时支持点选。 |

宽度均指应用窗口及其内容区的实际可用宽度。当前适配针对可连续显示的折叠屏，不包含双屏物理铰链遮挡区域的检测。

## 正式组件与原创代码

| 部分 | 采用方式 | 源文件 |
| --- | --- | --- |
| MiuixTheme、Scaffold、IconButton、Switch、OverlayDialog | 正式库 `miuix-ui:0.9.4` | [FoldConsole.kt](ui/src/main/java/com/gkeyes/lhasa26/ui/FoldConsole.kt) |
| Text、BasicComponent、LinearProgressIndicator | 正式库组件配合定制分栏与状态布局 | [FoldPages.kt](ui/src/main/java/com/gkeyes/lhasa26/ui/FoldPages.kt) |
| TextButton、ButtonDefaults | 正式交互语义配合原创的按压光泽和完整圆角 | [FoldActionButton.kt](ui/src/main/java/com/gkeyes/lhasa26/ui/FoldActionButton.kt) |
| 主状态卡 | 为 18fold 绘制的局部折面、深浅材质和边缘光 | [FoldStatusGlass.kt](ui/src/main/java/com/gkeyes/lhasa26/ui/FoldStatusGlass.kt) |
| 导航及折射 | 参考上游示例的交互原则，单独实现胶囊、方向切换、触点映射、图层采样和 AGSL | [FoldNavigation.kt](ui/src/main/java/com/gkeyes/lhasa26/ui/FoldNavigation.kt) · [FoldGlass.kt](ui/src/main/java/com/gkeyes/lhasa26/ui/FoldGlass.kt) |

上游发布页和示例均固定到使用的标签。[Miuix v0.9.4](https://github.com/compose-miuix-ui/miuix/releases/tag/v0.9.4) · [液态玻璃示例源码](https://github.com/compose-miuix-ui/miuix/tree/v0.9.4/example/shared/src/commonMain/kotlin/component/liquid)

## 接口与宿主迁移

1. Compose 公共入口为 `FoldConsole(state, onEvent)`。已有 Android View 布局可以使用 `FoldConsoleView`，其宿主需要提供 AndroidX 生命周期和保存状态所有者。为嵌入的 View 设置稳定 ID，可在宿主重建后恢复界面导航状态。
2. `FoldUiState` 接受已观测的授权状态、会话结果、按键可用性、设备字段和日志。初始化时显示未知或正在读取；界面不会因为用户按下按钮而自行宣布授权成功。开启常亮与实际导出结果由宿主回传。
3. `FoldEvent` 是界面意图。条件确认在界面层完成，路由时应避免在宿主再次显示相同确认框。版本、日志和配置以宿主现有数据为准。[状态和事件定义](ui/src/main/java/com/gkeyes/lhasa26/ui/FoldUiState.kt) · [View 入口](ui/src/main/java/com/gkeyes/lhasa26/ui/FoldConsoleView.kt)
4. 采用此版本时，先在独立库验证 UI，再由宿主对齐编译工具链、完成状态映射，最后在实际外屏／内屏验收。本仓库原发布工程使用 AGP 8.9.2 和 compileSdk 35。发布的 Miuix Android AAR 要求 compileSdk 37，所选 Compose AAR 同时要求 AGP 至少 9.1.0。本模块的最低安装要求为 Android 17（API 37），宿主接入时须采用同一最低要求。

## 独立构建

使用完整 JDK 17 和 Android SDK Platform 37。在本目录运行下面的命令，只编译该界面库。

```sh
./gradlew :ui:assembleDebug :ui:assembleRelease
```

构建锁定 Gradle 9.9.1、AGP 9.4.1、Kotlin Compose 插件 2.4.20、AndroidX Compose 1.12.0 和 Miuix 0.9.4。AAR 位于 `ui/build/outputs/aar/`。编译与最低系统版本均为 API 37。对用户手机生效的是最终安装包清单中的最低版本；旧版已发布 APK 不会被追溯修改。

## 验收口径

| 场景 | 可观察结果 |
| --- | --- |
| 首次进入或数据未返回 | 默认状态如实显示，主操作由宿主状态控制，授权入口可见。 |
| 快速拖动导航再松开、取消拖动、点击原标签 | 触点和胶囊连续，切页仅在点选或拖动确认后发生。 |
| 手机外屏切到内屏再收起 | 页面、日志和读到的位置保留；显示导航与正文宽度相适应。 |
| 日间、夜间、放大字号 | 纯白或纯黑底保持完整；焦点、按钮标签、内核长字符串和状态信息可读。 |
| 返回、取消维护、已禁用按钮 | 弹窗先关闭；取消不发操作事件；禁用状态不响应。 |
| 系列操作写入日志 | 记录页显示宿主回传文本，导出可以被独立调用。 |
