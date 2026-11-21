package com.gkeyes.lhasa26.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.RoundedCornerShape
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme

/** Native entry point. Only navigation and dialogs are local; operation results always come from [state]. */
@Composable
fun FoldConsole(
    state: FoldUiState,
    onEvent: (FoldEvent) -> Unit,
    modifier: Modifier = Modifier,
    dark: Boolean = isSystemInDarkTheme(),
    brandName: String = "18fold越狱",
) {
    var page by rememberSaveable { mutableIntStateOf(0) }
    var dialog by rememberSaveable { mutableStateOf<FoldEvent?>(null) }
    val offsets = listOf(rememberScrollState(), rememberScrollState(), rememberScrollState())
    val onRequest: (FoldEvent) -> Unit = { intent ->
        when (intent) {
            FoldEvent.HELP, FoldEvent.SETTINGS, FoldEvent.CLEAN, FoldEvent.SOFT_REBOOT, FoldEvent.REBOOT -> dialog = intent
            else -> onEvent(intent)
        }
    }
    BackHandler(enabled = dialog == null && page != 0) { page = 0 }
    val colors = remember(dark) {
        if (dark) darkColorScheme(
            primary = Color(0xff82d8b9), onPrimary = Color(0xff092a20),
            primaryVariant = Color(0xff82d8b9), background = Color.Black,
            surface = Color.Black, onBackground = Color(0xfff1f6f3),
            onSurface = Color(0xfff1f6f3), onSurfaceVariantSummary = Color(0xffadbcb5),
            secondary = Color(0xff1a2722), onSecondary = Color(0xffd2ebe1),
            surfaceContainer = Color(0xff15221d), dividerLine = Color(0xff343b37),
        ) else lightColorScheme(
            primary = Color(0xff096250), onPrimary = Color.White,
            primaryVariant = Color(0xff096250), background = Color.White,
            surface = Color.White, onBackground = Color(0xff102322),
            onSurface = Color(0xff102322), onSurfaceVariantSummary = Color(0xff50635d),
            secondary = Color(0xffe7efeb), onSecondary = Color(0xff173c30),
            surfaceContainer = Color(0xffedf4f0), dividerLine = Color(0xffd8dfdb),
        )
    }
    MiuixTheme(colors = colors) {
        Scaffold(modifier = modifier.fillMaxSize(), containerColor = colors.surface) { safe ->
            FoldGlassHost {
                BoxWithConstraints(Modifier.fillMaxSize().padding(safe)) {
                    val rail = maxWidth >= 700.dp
                    val margin = if (rail) 28.dp else 22.dp
                    val railSpace = if (rail) 96.dp else 0.dp
                    val usable = maxWidth - railSpace - margin * 2
                    val wide = usable >= 720.dp && LocalDensity.current.fontScale <= 1.35f
                    Box(
                        Modifier.fillMaxSize().foldGlassSource().padding(start = railSpace),
                        contentAlignment = Alignment.TopCenter,
                    ) {
                        key(page) {
                            Column(
                                Modifier.widthIn(max = if (wide) 1000.dp else 640.dp)
                                    .fillMaxSize().verticalScroll(offsets[page])
                                    .padding(horizontal = margin)
                                    .padding(top = if (rail) 26.dp else 18.dp, bottom = if (rail) 32.dp else 100.dp),
                            ) {
                                FoldHeader(page, brandName) { dialog = FoldEvent.SETTINGS }
                                Spacer(Modifier.height(24.dp))
                                FoldPages(page, state, onRequest, { page = 2 }, dark, wide)
                            }
                        }
                    }
                    val placement = if (rail) Modifier.align(Alignment.CenterStart).padding(start = 10.dp)
                        else Modifier.align(Alignment.BottomCenter).padding(start = 16.dp, end = 16.dp, bottom = 10.dp)
                    FoldNavigation(page, { page = it }, rail, dark, placement)
                }
            }
            FoldDialog(dialog, state, onDismiss = { dialog = null }, onEvent = onEvent)
        }
    }
}

@Composable
private fun FoldHeader(page: Int, brandName: String, settings: () -> Unit) {
    val colors = MiuixTheme.colorScheme
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                Image(painterResource(R.drawable.fold_brand), null,
                    modifier = Modifier.size(24.dp).clip(RoundedCornerShape(6.dp)))
                Text(brandName, color = colors.onSurfaceVariantSummary, fontSize = 13.sp, fontWeight = FontWeight.Medium)
            }
            Text(listOf("控制台", "设备", "记录")[page], modifier = Modifier.semantics { heading() },
                color = colors.onBackground, fontSize = 34.sp, lineHeight = 42.sp, fontWeight = FontWeight.Bold)
        }
        IconButton(onClick = settings, minWidth = 48.dp, minHeight = 48.dp, cornerRadius = 24.dp,
            backgroundColor = colors.surfaceContainer) {
            Image(painterResource(R.drawable.fold_settings), "设置", colorFilter = ColorFilter.tint(colors.onSurface))
        }
    }
}

@Composable
private fun FoldDialog(request: FoldEvent?, state: FoldUiState, onDismiss: () -> Unit, onEvent: (FoldEvent) -> Unit) {
    var lastRequest by remember { mutableStateOf(request) }
    SideEffect { if (request != null) lastRequest = request }
    val event = request ?: lastRequest ?: return
    val copy = when (event) {
        FoldEvent.SETTINGS -> "设置" to null
        FoldEvent.HELP -> "使用帮助" to "控制台显示授权与会话状态，设备页提供设备信息与维护入口，记录页可查看和导出本次日志。"
        FoldEvent.CLEAN -> "清理临时文件" to "将清理本次日志及临时诊断文件。确认继续？"
        FoldEvent.SOFT_REBOOT -> "软重启" to "系统服务将重新启动，界面可能短暂消失。确认继续？"
        FoldEvent.REBOOT -> "重启设备" to "设备将立即重启，当前临时会话会结束。确认继续？"
        else -> return
    }
    val needsConfirmation = event == FoldEvent.CLEAN || event == FoldEvent.SOFT_REBOOT || event == FoldEvent.REBOOT
    OverlayDialog(show = request != null, title = copy.first, summary = copy.second,
        backgroundColor = MiuixTheme.colorScheme.surfaceContainer, onDismissRequest = onDismiss) {
        Column(Modifier.fillMaxWidth()) {
            if (event == FoldEvent.SETTINGS) {
                BasicComponent(title = "保持屏幕常亮", insideMargin = PaddingValues(vertical = 6.dp),
                    endActions = { Switch(checked = state.keepScreenOn, onCheckedChange = { onEvent(FoldEvent.KEEP_ON) }) })
                BasicComponent(title = "外观", summary = "跟随系统", insideMargin = PaddingValues(vertical = 6.dp))
                if (state.version.isNotBlank()) {
                    BasicComponent(title = "版本", summary = state.version, insideMargin = PaddingValues(vertical = 6.dp))
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.End)) {
                if (needsConfirmation) {
                    TextButton("取消", onClick = onDismiss, minHeight = 48.dp)
                    TextButton("确认", onClick = { if (request == event) { onDismiss(); onEvent(event) } }, minHeight = 48.dp)
                } else {
                    TextButton("完成", onClick = onDismiss, minHeight = 48.dp)
                }
            }
        }
    }
}
