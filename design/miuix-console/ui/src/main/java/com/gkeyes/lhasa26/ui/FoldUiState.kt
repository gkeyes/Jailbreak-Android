package com.gkeyes.lhasa26.ui

import androidx.compose.runtime.Immutable

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
)

enum class FoldEvent {
    PRIMARY, AUTHORIZE, DIAGNOSE, EXPORT, CLEAN, SOFT_REBOOT, REBOOT, HELP, SETTINGS, KEEP_ON,
}
