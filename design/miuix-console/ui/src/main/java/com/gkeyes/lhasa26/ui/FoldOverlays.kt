package com.gkeyes.lhasa26.ui

import androidx.compose.animation.EnterTransition
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.DropdownEntry
import top.yukonga.miuix.kmp.basic.DropdownItem
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.blur.Backdrop
import top.yukonga.miuix.kmp.glass.GlassBottomSheet
import top.yukonga.miuix.kmp.glass.GlassDialog
import top.yukonga.miuix.kmp.glass.GlassDialogButton
import top.yukonga.miuix.kmp.glass.GlassDialogButtonRole
import top.yukonga.miuix.kmp.glass.GlassIconButton
import top.yukonga.miuix.kmp.glass.GlassIconDropdownMenu
import top.yukonga.miuix.kmp.glass.GlassMotion
import top.yukonga.miuix.kmp.glass.GlassPopupAnchor
import top.yukonga.miuix.kmp.glass.glassPopupAnchor
import top.yukonga.miuix.kmp.glass.glassPopupAnchorContent
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.glass.More
import top.yukonga.miuix.kmp.overlay.OverlayBottomSheet
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.MiuixPopupUtils.Companion.PopupLayout

@Composable
internal fun FoldMoreButton(anchor: GlassPopupAnchor, backdrop: Backdrop?, onClick: () -> Unit) {
    val size = 48.dp
    if (backdrop == null) {
        IconButton(onClick = onClick, minWidth = size, minHeight = size, cornerRadius = size / 2) {
            MoreIcon("更多")
        }
    } else {
        GlassIconButton(
            onClick = onClick, backdrop = backdrop, size = size,
            modifier = Modifier.glassPopupAnchor(anchor, cornerRadius = size / 2),
        ) {
            MoreIcon("更多", Modifier.glassPopupAnchorContent(anchor))
        }
    }
}

@Composable
private fun MoreIcon(description: String?, modifier: Modifier = Modifier) {
    Icon(imageVector = MiuixIcons.Glass.More, contentDescription = description, modifier = modifier.size(28.dp))
}

@Composable
internal fun FoldMoreMenu(
    show: Boolean,
    anchor: GlassPopupAnchor,
    backdrop: Backdrop?,
    onDismiss: () -> Unit,
    onRequest: (FoldEvent) -> Unit,
) {
    val request by rememberUpdatedState(onRequest)
    val entries = remember {
        listOf(DropdownEntry(listOf(
            DropdownItem(text = "设置", onClick = { request(FoldEvent.SETTINGS) }),
            DropdownItem(text = "使用帮助", onClick = { request(FoldEvent.HELP) }),
        )))
    }
    if (backdrop == null) {
        OverlayDialog(show = show, title = "更多", onDismissRequest = onDismiss) {
            Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
                entries.single().items.forEach { item ->
                    BasicComponent(
                        title = item.text,
                        insideMargin = PaddingValues(vertical = 12.dp),
                        role = Role.Button,
                        onClick = {
                            if (show) {
                                onDismiss()
                                item.onClick?.invoke()
                            }
                        },
                    )
                }
                Spacer(Modifier.height(8.dp))
                TextButton("取消", onClick = onDismiss, modifier = Modifier.fillMaxWidth())
            }
        }
        return
    }
    val hostVisible = remember { mutableStateOf(show) }
    SideEffect { hostVisible.value = show }
    PopupLayout(
        visible = hostVisible,
        enableWindowDim = false,
        enableBackHandler = false,
        enterTransition = EnterTransition.None,
        exitTransition = fadeOut(GlassMotion.transformBounds(false)),
    ) {
        // Let the popup enter from the measured toolbar icon after the host is mounted.
        var expanded by remember { mutableStateOf(false) }
        LaunchedEffect(show) { expanded = show }
        Box(Modifier.fillMaxSize()) {
            GlassIconDropdownMenu(
                show = expanded,
                onDismissRequest = onDismiss,
                anchor = anchor,
                anchorContent = { MoreIcon(null) },
                entries = entries,
                backdrop = backdrop,
            )
        }
    }
}

@Composable
internal fun FoldDialogs(
    request: FoldEvent?,
    state: FoldUiState,
    backdrop: Backdrop?,
    onDismiss: () -> Unit,
    onEvent: (FoldEvent) -> Unit,
) {
    var previous by remember { mutableStateOf(request) }
    SideEffect { if (request != null) previous = request }
    val event = request ?: previous ?: return
    var open by remember(request) { mutableStateOf(request != null) }
    val dismiss = {
        if (open) {
            open = false
            onDismiss()
        }
    }
    val glass = backdrop != null
    if (event == FoldEvent.HELP) {
        val help: @Composable () -> Unit = {
            Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).navigationBarsPadding()) {
                BasicComponent(title = "控制台", summary = "查看授权与会话状态。", insideMargin = PaddingValues(vertical = 7.dp))
                BasicComponent(title = "设备", summary = "查看设备信息，使用设备维护工具。", insideMargin = PaddingValues(vertical = 7.dp))
                BasicComponent(title = "记录", summary = "查看和导出本次会话的日志。", insideMargin = PaddingValues(vertical = 7.dp))
                Spacer(Modifier.height(12.dp))
                DialogAction("完成", GlassDialogButtonRole.Primary, glass, dismiss, Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
            }
        }
        if (glass) {
            GlassBottomSheet(onDismissRequest = dismiss, show = open, backdrop = backdrop, title = "使用帮助", content = help)
        } else {
            OverlayBottomSheet(show = open, onDismissRequest = dismiss, title = "使用帮助", content = help)
        }
        return
    }

    val (title, summary) = when (event) {
        FoldEvent.SETTINGS -> "设置" to null
        FoldEvent.CLEAN -> "清理临时文件" to "将清理本次日志及临时诊断文件。确认继续？"
        FoldEvent.SOFT_REBOOT -> "软重启" to "系统服务将重新启动，界面可能短暂消失。确认继续？"
        FoldEvent.REBOOT -> "重启设备" to "设备将立即重启，当前临时会话会结束。确认继续？"
        else -> return
    }
    val content: @Composable () -> Unit = {
        if (event == FoldEvent.SETTINGS) {
            Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
                BasicComponent(title = "保持屏幕常亮", insideMargin = PaddingValues(vertical = 8.dp),
                    endActions = {
                        Switch(checked = state.keepScreenOn, onCheckedChange = { if (open) onEvent(FoldEvent.KEEP_ON) })
                    })
                BasicComponent(title = "外观", summary = "跟随系统", insideMargin = PaddingValues(vertical = 6.dp))
                if (state.version.isNotBlank()) {
                    BasicComponent(title = "版本", summary = state.version, insideMargin = PaddingValues(vertical = 6.dp))
                }
                Spacer(Modifier.height(12.dp))
                DialogAction("完成", GlassDialogButtonRole.Primary, glass, dismiss, Modifier.fillMaxWidth())
            }
        } else {
            val action = when (event) {
                FoldEvent.CLEAN -> "清理"
                FoldEvent.SOFT_REBOOT -> "软重启"
                else -> "重启"
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                DialogAction("取消", GlassDialogButtonRole.Normal, glass, dismiss, Modifier.weight(1f))
                DialogAction(action, GlassDialogButtonRole.Destructive, glass, {
                    if (open) {
                        dismiss()
                        onEvent(event)
                    }
                }, Modifier.weight(1f))
            }
        }
    }
    if (glass) {
        GlassDialog(onDismissRequest = dismiss, show = open, backdrop = backdrop, title = title, summary = summary, content = content)
    } else {
        OverlayDialog(show = open, onDismissRequest = dismiss, title = title, summary = summary, content = content)
    }
}

@Composable
private fun DialogAction(label: String, role: GlassDialogButtonRole, glass: Boolean, onClick: () -> Unit, modifier: Modifier) {
    if (glass) {
        GlassDialogButton(onClick = onClick, role = role, modifier = modifier) {
            Text(label, style = MiuixTheme.textStyles.button)
        }
    } else {
        val colors = when (role) {
            GlassDialogButtonRole.Primary -> ButtonDefaults.textButtonColorsPrimary()
            GlassDialogButtonRole.Destructive -> ButtonDefaults.textButtonColors(textColor = MiuixTheme.colorScheme.error)
            GlassDialogButtonRole.Normal -> ButtonDefaults.textButtonColors()
        }
        TextButton(text = label, onClick = onClick, modifier = modifier, colors = colors, minHeight = 50.dp)
    }
}
