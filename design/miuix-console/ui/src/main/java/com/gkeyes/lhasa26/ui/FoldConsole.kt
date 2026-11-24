package com.gkeyes.lhasa26.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberTopAppBarState
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.blur.rememberLayerBackdrop
import top.yukonga.miuix.kmp.glass.GlassIconButton
import top.yukonga.miuix.kmp.glass.GlassNavigationRailDefaults
import top.yukonga.miuix.kmp.glass.GlassTopAppBar
import top.yukonga.miuix.kmp.glass.rememberGlassPopupAnchor
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.glass.SettingsOutline
import top.yukonga.miuix.kmp.material.isRuntimeShaderSupported
import top.yukonga.miuix.kmp.squircle.LocalSquircleEnabled
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical

private val pageNames = listOf("控制台", "设备", "记录")

/** Navigation and overlays stay local. Display values and operation results come from the host. */
@Composable
fun FoldConsole(
    state: FoldUiState,
    onEvent: (FoldEvent) -> Unit,
    modifier: Modifier = Modifier,
    dark: Boolean = isSystemInDarkTheme(),
    brandName: String = "18fold越狱",
    hardwareEffectsEnabled: Boolean = true,
) {
    var page by rememberSaveable { mutableIntStateOf(0) }
    var dialog by rememberSaveable { mutableStateOf<FoldEvent?>(null) }
    var menuOpen by rememberSaveable { mutableStateOf(false) }
    val offsets = listOf(rememberScrollState(), rememberScrollState(), rememberScrollState())
    val barStates = listOf(rememberTopAppBarState(), rememberTopAppBarState(), rememberTopAppBarState())
    val onRequest: (FoldEvent) -> Unit = { intent ->
        when (intent) {
            FoldEvent.HELP, FoldEvent.SETTINGS, FoldEvent.CLEAN, FoldEvent.SOFT_REBOOT, FoldEvent.REBOOT -> {
                menuOpen = false
                dialog = intent
            }
            else -> onEvent(intent)
        }
    }
    BackHandler(enabled = dialog == null && !menuOpen && page != 0) { page = 0 }
    BackHandler(enabled = menuOpen) { menuOpen = false }

    val hardware = hardwareEffectsEnabled && LocalView.current.isHardwareAccelerated &&
        LocalSquircleEnabled.current && isRuntimeShaderSupported()
    val scheme = remember(dark) { if (dark) darkColorScheme() else lightColorScheme() }
    CompositionLocalProvider(LocalSquircleEnabled provides hardware) {
        MiuixTheme(colors = scheme) {
            val surface = MiuixTheme.colorScheme.surface
            val body = if (hardware) rememberLayerBackdrop { drawRect(surface); drawContent() } else null
            val wholePage = if (hardware) rememberLayerBackdrop { drawRect(surface); drawContent() } else null
            val anchor = rememberGlassPopupAnchor()
            val behavior = MiuixScrollBehavior(barStates[page])
            val horizontalSafe = WindowInsets.displayCutout.union(WindowInsets.navigationBars).only(WindowInsetsSides.Horizontal)
            // The outer scaffold owns Miuix's popup/dialog host. Its popup slot is outside both recordings.
            Scaffold(modifier = modifier.fillMaxSize(), contentWindowInsets = WindowInsets(0, 0, 0, 0)) { _ ->
                BoxWithConstraints(Modifier.fillMaxSize()) {
                    val safe = horizontalSafe.asPaddingValues()
                    val layoutDirection = LocalLayoutDirection.current
                    val density = LocalDensity.current
                    // A fold or display-size change can update density with identical pixel constraints.
                    val width = with(density) { constraints.maxWidth.toDp() } -
                        safe.calculateLeftPadding(layoutDirection) - safe.calculateRightPadding(layoutDirection)
                    val rail = width >= 700.dp
                    val start = when {
                        !rail -> 0.dp
                        hardware -> foldRailWidth + GlassNavigationRailDefaults.Margin
                        else -> foldRailWidth
                    }
                    val wide = width - start - foldWideGutter * 3 >= 720.dp && density.fontScale <= 1.35f
                    val topBarModifier = if (rail) {
                        Modifier.windowInsetsPadding(horizontalSafe.only(WindowInsetsSides.Start)).padding(start = start)
                    } else Modifier
                    val actions: @Composable RowScope.() -> Unit = {
                        if (hardware) {
                            GlassIconButton(onClick = { onRequest(FoldEvent.SETTINGS) }, backdrop = body) {
                                SettingsIcon()
                            }
                        } else {
                            IconButton(onClick = { onRequest(FoldEvent.SETTINGS) }) { SettingsIcon() }
                        }
                        FoldMoreButton(anchor, body) { menuOpen = true }
                    }

                    // This inner scaffold only lays out bars and body. It never renders an overlay.
                    Scaffold(
                        modifier = Modifier.fillMaxSize().recordedBy(wholePage),
                        popupHost = {},
                        topBar = {
                            if (hardware) {
                                GlassTopAppBar(
                                    title = pageNames[page], subtitle = brandName,
                                    modifier = topBarModifier,
                                    backdrop = body, progressiveBlur = true,
                                    scrollBehavior = behavior, actions = actions,
                                )
                            } else {
                                TopAppBar(
                                    title = pageNames[page], subtitle = brandName,
                                    modifier = topBarModifier,
                                    scrollBehavior = behavior, actions = actions,
                                )
                            }
                        },
                        bottomBar = {
                            if (!rail) {
                                val navModifier = if (hardware) Modifier.padding(horizontal = 16.dp, vertical = 8.dp) else Modifier
                                FoldNavigation(page, { page = it }, rail = false, backdrop = body, modifier = navModifier)
                            }
                        },
                    ) { padding ->
                        Box(Modifier.fillMaxSize()) {
                            Box(
                                Modifier.fillMaxSize().recordedBy(body).background(surface)
                                    .windowInsetsPadding(horizontalSafe).padding(start = start),
                                contentAlignment = Alignment.TopCenter,
                            ) {
                                key(page) {
                                    Column(
                                        Modifier.widthIn(max = if (wide) 1000.dp else 640.dp).fillMaxSize()
                                            .overScrollVertical(onOffsetChanged = { behavior.state.overscrollOffset = it })
                                            .nestedScroll(behavior.nestedScrollConnection)
                                            .verticalScroll(offsets[page], overscrollEffect = null)
                                            .padding(top = padding.calculateTopPadding(), bottom = padding.calculateBottomPadding() + 12.dp),
                                    ) {
                                        FoldPages(page, state, onRequest, { page = 2 }, wide)
                                    }
                                }
                            }
                            if (rail) {
                                FoldNavigation(page, { page = it }, rail = true, backdrop = body)
                            }
                        }
                    }
                    FoldMoreMenu(menuOpen, anchor, wholePage, onDismiss = { menuOpen = false }, onRequest = onRequest)
                    FoldDialogs(dialog, state, brandName, wholePage, onDismiss = { dialog = null }, onEvent = onEvent)
                }
            }
        }
    }
}

private fun Modifier.recordedBy(backdrop: LayerBackdrop?): Modifier =
    if (backdrop == null) this else layerBackdrop(backdrop)

@Composable
private fun SettingsIcon() {
    Icon(MiuixIcons.Glass.SettingsOutline, contentDescription = "设置", modifier = Modifier.size(28.dp))
}
