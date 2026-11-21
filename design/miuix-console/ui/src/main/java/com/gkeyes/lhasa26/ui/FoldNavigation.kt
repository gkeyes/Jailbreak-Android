package com.gkeyes.lhasa26.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import top.yukonga.miuix.kmp.basic.NavigationBar
import top.yukonga.miuix.kmp.basic.NavigationBarItem
import top.yukonga.miuix.kmp.basic.NavigationRail
import top.yukonga.miuix.kmp.basic.NavigationRailItem
import top.yukonga.miuix.kmp.blur.Backdrop
import top.yukonga.miuix.kmp.glass.GlassNavigationBar
import top.yukonga.miuix.kmp.glass.GlassNavigationItem
import top.yukonga.miuix.kmp.glass.GlassNavigationRail
import top.yukonga.miuix.kmp.glass.rememberGlassNavigationRailState
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.glass.FoldingScreenMyDevice
import top.yukonga.miuix.kmp.icon.glass.HomeOutline
import top.yukonga.miuix.kmp.icon.glass.Log
import top.yukonga.miuix.kmp.squircle.LocalSquircleEnabled
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme

internal val foldRailWidth = 190.dp

/** Standalone navigation is also usable in a window without a recorded scene. */
@Composable
fun FoldNavigation(
    selected: Int,
    onSelect: (Int) -> Unit,
    rail: Boolean,
    dark: Boolean,
    modifier: Modifier = Modifier,
) {
    CompositionLocalProvider(LocalSquircleEnabled provides false) {
        MiuixTheme(colors = if (dark) darkColorScheme() else lightColorScheme()) {
            FoldNavigation(selected, onSelect, rail, backdrop = null, modifier = modifier)
        }
    }
}

@Composable
internal fun FoldNavigation(
    selected: Int,
    onSelect: (Int) -> Unit,
    rail: Boolean,
    backdrop: Backdrop?,
    modifier: Modifier = Modifier,
) {
    val tabs = remember {
        listOf(
            GlassNavigationItem(MiuixIcons.Glass.HomeOutline, "控制台", "控制台"),
            GlassNavigationItem(MiuixIcons.Glass.FoldingScreenMyDevice, "设备", "设备"),
            GlassNavigationItem(MiuixIcons.Glass.Log, "记录", "记录"),
        )
    }
    if (backdrop != null) {
        if (rail) {
            GlassNavigationRail(
                items = tabs, selectedIndex = selected, onSelect = onSelect,
                backdrop = backdrop, modifier = modifier,
                state = rememberGlassNavigationRailState(initialExpanded = true),
                expandedWidth = foldRailWidth, showToggle = false,
            )
        } else {
            GlassNavigationBar(
                items = tabs, selectedIndex = selected, onSelect = onSelect,
                backdrop = backdrop, modifier = modifier,
            )
        }
    } else if (rail) {
        NavigationRail(modifier = modifier, expanded = true, expandedWidth = foldRailWidth) {
            tabs.forEachIndexed { index, item ->
                NavigationRailItem(selected == index, { onSelect(index) }, item.icon, item.label.orEmpty())
            }
        }
    } else {
        NavigationBar(modifier = modifier) {
            tabs.forEachIndexed { index, item ->
                NavigationBarItem(selected == index, { onSelect(index) }, item.icon, item.label.orEmpty())
            }
        }
    }
}
