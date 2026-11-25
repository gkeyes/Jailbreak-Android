package com.gkeyes.lhasa26.ui

import androidx.compose.runtime.Immutable

/**
 * 提权路径的持久化键，必须和 core `RootPath.key()` 保持一致（宿主用字符串传值，
 * UI 模块不依赖 app 模块的 core 包）。
 */
const val ROOT_PATH_TIMER_98260 = "TIMER_98260"
const val ROOT_PATH_WACOM_99491 = "WACOM_99491"

/** Current display values supplied by the host. Unknown and busy states are represented explicitly. */
@Immutable
data class FoldUiState(
    val status: String = "正在读取状态",
    val privilege: String = "未知",
    val authorization: String = "检测中",
    val actionLabel: String = "一键临时 ROOT",
    val step: String = "",
    val elapsed: String = "",
    val device: String = "—",
    val build: String = "—",
    val kernel: String = "—",
    val compatibility: String = "待检测",
    val log: String = "",
    val latest: String = "",
    val primaryEnabled: Boolean = false,
    val authorizationEnabled: Boolean = false,
    val diagnosticEnabled: Boolean = false,
    val running: Boolean = false,
    val progressVisible: Boolean = false,
    val keepScreenOn: Boolean = true,
    val progress: Float = 0f,
    val version: String = "",
    /** 当前选中的提权路径：98260（默认）或 99491（opt-in）。 */
    val rootPath: String = ROOT_PATH_TIMER_98260,
    /**
     * 99491 profile 是否可用（release 精确匹配 + verified）。
     * fail-closed：未校验 / 校验中 / 不可用一律 false，此时系统面板的 99491 行禁用并显示原因。
     */
    val rootPathAvailable: Boolean = false,
    /** 99491 不可用（或 debug 放宽）的原因，直接展示给用户。 */
    val rootPathNote: String = "",
)

enum class FoldEvent {
    PRIMARY, AUTHORIZE, DIAGNOSE, EXPORT, CLEAN, SOFT_REBOOT, REBOOT, HELP, SETTINGS, KEEP_ON,

    /** 在 98260 / 99491 之间切换提权路径（未适配的 99491 会被宿主拒绝并提示原因）。 */
    PATH_SELECT,
}
