package com.gkeyes.lhasa26.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun FoldPages(
    page: Int,
    state: FoldUiState,
    onEvent: (FoldEvent) -> Unit,
    onRecords: () -> Unit,
    dark: Boolean,
    wide: Boolean,
) {
    when (page) {
        0 -> {
            if (wide) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(28.dp)) {
                    Column(Modifier.weight(1.12f)) { SessionPanel(state, onEvent, dark) }
                    Column(Modifier.weight(1f)) { HomeDetails(state, onEvent, onRecords) }
                }
            } else {
                Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(28.dp)) {
                    SessionPanel(state, onEvent, dark)
                    HomeDetails(state, onEvent, onRecords)
                }
            }
        }
        1 -> DevicePage(state, onEvent, wide)
        2 -> RecordsPage(state, onEvent)
    }
}

@Composable
private fun SessionPanel(state: FoldUiState, onEvent: (FoldEvent) -> Unit, dark: Boolean) {
    val colors = MiuixTheme.colorScheme
    FoldStatusGlass(modifier = Modifier.fillMaxWidth(), dark = dark) {
        Column(Modifier.fillMaxWidth().padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(Modifier.size(8.dp).background(colors.primary, CircleShape))
                Text("临时 ROOT", Modifier.weight(1f), color = colors.onBackground, fontSize = 15.sp,
                    fontWeight = FontWeight.Medium)
                Text(state.privilege, color = colors.onSurfaceVariantSummary, fontSize = 14.sp)
            }
            Spacer(Modifier.height(16.dp))
            Text(
                state.status,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                color = colors.onBackground,
                fontSize = 28.sp, lineHeight = 35.sp, fontWeight = FontWeight.SemiBold,
            )
            if (state.progressVisible) {
                Spacer(Modifier.height(14.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(state.step, Modifier.weight(1f), color = colors.onSurfaceVariantSummary,
                        fontSize = 13.sp, lineHeight = 19.sp)
                    if (state.elapsed.isNotBlank()) {
                        Text(state.elapsed, color = colors.onSurfaceVariantSummary, fontSize = 13.sp)
                    }
                }
                Spacer(Modifier.height(8.dp))
                LinearProgressIndicator(
                    progress = if (state.running && state.progress <= 0f) null else state.progress.coerceIn(0f, 1f),
                    height = 4.dp,
                )
            }
            Spacer(Modifier.height(20.dp))
            FoldActionButton(
                text = state.actionLabel,
                onClick = { onEvent(FoldEvent.PRIMARY) },
                modifier = Modifier.fillMaxWidth(),
                enabled = state.primaryEnabled,
                primary = true,
            )
        }
    }
}

@Composable
private fun HomeDetails(state: FoldUiState, onEvent: (FoldEvent) -> Unit, onRecords: () -> Unit) {
    val colors = MiuixTheme.colorScheme
    Column(Modifier.fillMaxWidth()) {
        SectionHeading("连接与授权")
        Spacer(Modifier.height(8.dp))
        BoxWithConstraints(Modifier.fillMaxWidth()) {
            val stack = maxWidth < 300.dp || LocalDensity.current.fontScale >= 1.3f
            val authorize: @Composable () -> Unit = {
                FoldActionButton("Shizuku 授权", onClick = { onEvent(FoldEvent.AUTHORIZE) },
                    enabled = state.authorizationEnabled)
            }
            if (stack) {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    BasicComponent(title = "Shizuku", summary = state.authorization,
                        insideMargin = PaddingValues(vertical = 4.dp))
                    authorize()
                }
            } else {
                BasicComponent(title = "Shizuku", summary = state.authorization,
                    insideMargin = PaddingValues(vertical = 4.dp), endActions = { authorize() })
            }
        }
        Spacer(Modifier.height(18.dp))
        Rule()
        BasicComponent(
            insideMargin = PaddingValues(vertical = 14.dp),
            endActions = { Chevron() },
            onClick = onRecords, onClickLabel = "查看最近记录", role = Role.Button,
        ) {
            SectionHeading("最近记录")
            Spacer(Modifier.height(4.dp))
            val hasEntry = state.latest.isNotBlank()
            Text(if (hasEntry) state.latest else "本次会话暂无记录",
                color = colors.onSurfaceVariantSummary, fontFamily = if (hasEntry) FontFamily.Monospace else null,
                fontSize = 14.sp, lineHeight = 21.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun DevicePage(state: FoldUiState, onEvent: (FoldEvent) -> Unit, wide: Boolean) {
    if (wide) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(32.dp)) {
            Column(Modifier.weight(1.12f)) { SystemDetails(state, onEvent) }
            Column(Modifier.weight(1f)) { Maintenance(onEvent) }
        }
    } else {
        Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(28.dp)) {
            SystemDetails(state, onEvent)
            Maintenance(onEvent)
        }
    }
}

@Composable
private fun SystemDetails(state: FoldUiState, onEvent: (FoldEvent) -> Unit) {
    Column(Modifier.fillMaxWidth()) {
        SectionHeading("系统信息")
        Spacer(Modifier.height(8.dp))
        BoxWithConstraints(Modifier.fillMaxWidth()) {
            val stack = maxWidth < 300.dp || LocalDensity.current.fontScale >= 1.3f
            Column {
                DeviceValue("设备代号", state.device, stack)
                Rule()
                DeviceValue("系统版本", state.build, stack)
                Rule()
                DeviceValue("内核版本", state.kernel, stack)
                Rule()
                DeviceValue("适配状态", state.compatibility, stack)
            }
        }
        Spacer(Modifier.height(10.dp))
        FoldActionButton("接口诊断", onClick = { onEvent(FoldEvent.DIAGNOSE) },
            modifier = Modifier.fillMaxWidth(),
            enabled = state.diagnosticEnabled)
    }
}

@Composable
private fun DeviceValue(label: String, value: String, stack: Boolean) {
    val colors = MiuixTheme.colorScheme
    val row = Modifier.fillMaxWidth().heightIn(min = 52.dp).padding(vertical = 10.dp)
    if (stack) {
        Column(row, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, color = colors.onSurfaceVariantSummary, fontSize = 14.sp)
            Text(value, color = colors.onBackground, fontSize = 15.sp, lineHeight = 21.sp)
        }
    } else {
        Row(row, verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            Text(label, color = colors.onSurfaceVariantSummary, fontSize = 14.sp)
            Text(value, Modifier.weight(1f), color = colors.onBackground, fontSize = 15.sp,
                lineHeight = 21.sp, textAlign = TextAlign.End)
        }
    }
}

@Composable
private fun Maintenance(onEvent: (FoldEvent) -> Unit) {
    Column(Modifier.fillMaxWidth()) {
        SectionHeading("设备维护")
        Spacer(Modifier.height(8.dp))
        ActionRow("清理临时文件") { onEvent(FoldEvent.CLEAN) }
        Rule()
        ActionRow("软重启") { onEvent(FoldEvent.SOFT_REBOOT) }
        Rule()
        ActionRow("重启设备") { onEvent(FoldEvent.REBOOT) }
        Rule()
        ActionRow("使用帮助") { onEvent(FoldEvent.HELP) }
    }
}

@Composable
private fun ActionRow(label: String, onClick: () -> Unit) {
    BasicComponent(title = label, insideMargin = PaddingValues(horizontal = 0.dp, vertical = 8.dp),
        onClick = onClick, role = Role.Button, endActions = { Chevron() })
}

@Composable
private fun Chevron() {
    val tint = MiuixTheme.colorScheme.onSurfaceVariantSummary
    val rtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    Canvas(Modifier.size(14.dp)) {
        val insideX = size.width * if (rtl) .62f else .38f
        val outsideX = size.width - insideX
        val center = Offset(outsideX, size.height * .5f)
        drawLine(tint, Offset(insideX, size.height * .22f), center, 1.5.dp.toPx(), StrokeCap.Round)
        drawLine(tint, center, Offset(insideX, size.height * .78f), 1.5.dp.toPx(), StrokeCap.Round)
    }
}

@Composable
private fun RecordsPage(state: FoldUiState, onEvent: (FoldEvent) -> Unit) {
    val colors = MiuixTheme.colorScheme
    Column(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            SectionHeading("本次会话", Modifier.weight(1f))
            FoldActionButton("导出日志", onClick = { onEvent(FoldEvent.EXPORT) })
        }
        Spacer(Modifier.height(8.dp))
        Rule()
        if (state.log.isBlank()) {
            Box(Modifier.fillMaxWidth().heightIn(min = 144.dp), contentAlignment = Alignment.Center) {
                Text("本次会话暂无记录", color = colors.onSurfaceVariantSummary, fontSize = 15.sp)
            }
        } else {
            SelectionContainer {
                Text(state.log, Modifier.fillMaxWidth().padding(vertical = 16.dp), color = colors.onBackground,
                    fontFamily = FontFamily.Monospace, fontSize = 14.sp, lineHeight = 22.sp)
            }
        }
    }
}

@Composable
private fun SectionHeading(text: String, modifier: Modifier = Modifier) {
    Text(text, modifier.semantics { heading() }, color = MiuixTheme.colorScheme.onBackground,
        fontSize = 19.sp, lineHeight = 26.sp, fontWeight = FontWeight.SemiBold)
}

@Composable
private fun Rule() {
    Spacer(Modifier.fillMaxWidth().height(1.dp).background(MiuixTheme.colorScheme.dividerLine))
}
