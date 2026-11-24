package com.gkeyes.lhasa26.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.basic.ArrowRight
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun FoldPages(
    page: Int,
    state: FoldUiState,
    onEvent: (FoldEvent) -> Unit,
    onRecords: () -> Unit,
    wide: Boolean,
) {
    when (page) {
        0 -> PageColumns(wide, {
            SessionPanel(state, onEvent)
        }, {
            AuthorizationPanel(state, onEvent)
            GroupCard("最近记录") {
                BasicComponent(
                    onClick = onRecords, onClickLabel = "查看本次会话的记录", role = Role.Button,
                    endActions = { OpenArrow() },
                ) {
                    Text(state.latest.ifBlank { "本次会话暂无记录" }, maxLines = 3, overflow = TextOverflow.Ellipsis)
                }
            }
        })
        1 -> PageColumns(wide, {
            SystemPanel(state, onEvent)
        }, {
            GroupCard("设备维护") {
                Operation("清理临时文件") { onEvent(FoldEvent.CLEAN) }
                Operation("软重启") { onEvent(FoldEvent.SOFT_REBOOT) }
                Operation("重启设备") { onEvent(FoldEvent.REBOOT) }
            }
            GroupCard("帮助") {
                Operation("使用帮助") { onEvent(FoldEvent.HELP) }
            }
        })
        2 -> PageColumns(wide, {
            GroupCard("本次会话") {
                val lineCount = remember(state.log) {
                    if (state.log.isBlank()) 0 else state.log.trimEnd('\r', '\n').lineSequence().count()
                }
                ActionSummary(
                    title = "运行日志", summary = "$lineCount 行日志", action = "导出日志",
                    onClick = { onEvent(FoldEvent.EXPORT) },
                )
                if (!wide) LogText(state.log)
            }
        }, {
            if (wide) GroupCard("运行记录") { LogText(state.log) }
        })
    }
}

@Composable
private fun SessionPanel(state: FoldUiState, onEvent: (FoldEvent) -> Unit) {
    GroupCard("会话状态") {
        BasicComponent(
            title = "临时 ROOT",
            summary = listOf(state.privilege, state.status).filter { it.isNotBlank() }.joinToString(" · "),
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
        if (state.progressVisible) {
            Column(Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 12.dp)) {
                val details = listOf(state.step, state.elapsed).filter { it.isNotBlank() }.joinToString(" · ")
                if (details.isNotEmpty()) {
                    Text(details, style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary)
                    Spacer(Modifier.height(8.dp))
                }
                LinearProgressIndicator(
                    progress = if (state.running && state.progress <= 0f) null else state.progress.coerceIn(0f, 1f),
                )
            }
        }
        TextButton(
            text = state.actionLabel,
            enabled = state.primaryEnabled, onClick = { onEvent(FoldEvent.PRIMARY) },
            colors = ButtonDefaults.textButtonColorsPrimary(),
            modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
        )
    }
}

@Composable
private fun AuthorizationPanel(state: FoldUiState, onEvent: (FoldEvent) -> Unit) {
    GroupCard("连接与授权") {
        ActionSummary(
            title = "Shizuku", summary = state.authorization, action = "Shizuku 授权",
            enabled = state.authorizationEnabled, onClick = { onEvent(FoldEvent.AUTHORIZE) },
        )
    }
}

@Composable
private fun ActionSummary(title: String, summary: String, action: String, enabled: Boolean = true, onClick: () -> Unit) {
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val stack = maxWidth < 300.dp || LocalDensity.current.fontScale >= 1.3f
        if (stack) {
            Column {
                BasicComponent(title = title, summary = summary)
                TextButton(text = action, onClick = onClick, enabled = enabled,
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp))
            }
        } else {
            BasicComponent(title = title, summary = summary,
                endActions = { TextButton(text = action, onClick = onClick, enabled = enabled) })
        }
    }
}

@Composable
private fun SystemPanel(state: FoldUiState, onEvent: (FoldEvent) -> Unit) {
    GroupCard("系统信息") {
        Spacer(Modifier.height(6.dp))
        BoxWithConstraints(Modifier.fillMaxWidth()) {
            val stack = maxWidth < 300.dp || LocalDensity.current.fontScale >= 1.3f
            Column {
                DeviceValue("设备代号", state.device, stack)
                DeviceValue("系统版本", state.build, stack)
                DeviceValue("内核版本", state.kernel, stack)
                DeviceValue("适配状态", state.compatibility, stack)
            }
        }
        Spacer(Modifier.height(4.dp))
        TextButton(
            text = "接口诊断", onClick = { onEvent(FoldEvent.DIAGNOSE) }, enabled = state.diagnosticEnabled,
            modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
        )
    }
}

@Composable
private fun DeviceValue(label: String, value: String, stack: Boolean) {
    val row = Modifier.fillMaxWidth().heightIn(min = 36.dp).padding(horizontal = 16.dp, vertical = 3.dp)
    if (stack) {
        Column(row, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, style = MiuixTheme.textStyles.body2, color = MiuixTheme.colorScheme.onSurfaceVariantSummary)
            Text(value)
        }
    } else {
        Row(row, horizontalArrangement = Arrangement.spacedBy(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(label)
            Text(value, modifier = Modifier.weight(1f), textAlign = TextAlign.End)
        }
    }
}

internal val foldWideGutter = 16.dp

@Composable
private fun PageColumns(
    wide: Boolean,
    first: @Composable ColumnScope.() -> Unit,
    second: @Composable ColumnScope.() -> Unit,
) {
    if (wide) {
        Row(Modifier.fillMaxWidth().padding(horizontal = foldWideGutter), horizontalArrangement = Arrangement.spacedBy(foldWideGutter)) {
            Column(Modifier.weight(1f), content = first)
            Column(Modifier.weight(1f), content = second)
        }
    } else {
        Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
            first()
            second()
        }
    }
}

@Composable
private fun GroupCard(label: String, content: @Composable ColumnScope.() -> Unit) {
    SmallTitle(label, modifier = Modifier.semantics { heading() },
        insideMargin = PaddingValues(start = 16.dp, top = 8.dp, bottom = 8.dp))
    Card(modifier = Modifier.fillMaxWidth(), content = content)
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun Operation(label: String, onClick: () -> Unit) {
    BasicComponent(title = label, endActions = { OpenArrow() },
        onClickLabel = label, onClick = onClick, role = Role.Button)
}

@Composable
private fun OpenArrow() {
    val rtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    Icon(MiuixIcons.Basic.ArrowRight, contentDescription = null, modifier = Modifier.scale(if (rtl) -1f else 1f, 1f))
}

@Composable
private fun LogText(log: String) {
    if (log.isBlank()) {
        BasicComponent(title = "本次会话暂无记录")
    } else {
        SelectionContainer {
            Text(log, modifier = Modifier.fillMaxWidth().padding(16.dp),
                fontFamily = FontFamily.Monospace, style = MiuixTheme.textStyles.body2)
        }
    }
}
