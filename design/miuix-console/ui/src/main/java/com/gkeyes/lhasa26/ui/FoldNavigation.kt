package com.gkeyes.lhasa26.ui

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import top.yukonga.miuix.kmp.basic.Text
import kotlin.math.roundToInt

private val destinations = listOf("控制台", "设备", "记录")

/** Floating, scrubbable glass navigation. Pass the parent's insets/placement via modifier. */
@Composable
fun FoldNavigation(
    selected: Int,
    onSelect: (Int) -> Unit,
    rail: Boolean,
    dark: Boolean,
    modifier: Modifier = Modifier,
) {
    val count = destinations.size
    val density = LocalDensity.current
    val currentOnSelect by rememberUpdatedState(onSelect)
    val isRtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    var dragPosition by remember(rail, isRtl) { mutableStateOf<Float?>(null) }
    // Keep pointer tracking direct. Start the release spring at the last touch position.
    val position = remember { Animatable(selected.toFloat()) }
    var releasePosition by remember(rail, isRtl) { mutableStateOf<Float?>(null) }
    val dragging = dragPosition != null
    LaunchedEffect(selected, dragging, rail, isRtl) {
        if (!dragging) {
            releasePosition?.let { position.snapTo(it) }
            releasePosition = null
            position.animateTo(selected.toFloat(), spring(dampingRatio = .79f, stiffness = 420f))
        }
    }
    val stretch by animateFloatAsState(if (dragPosition != null) 1.055f else 1f, label = "glass-navigation-press")
    val tabHeight = with(density) { (28.dp + 16.sp.toDp()).coerceAtLeast(52.dp) }
    val dockBounds = if (rail) {
        Modifier.width(76.dp).height(tabHeight * count + 10.dp)
    } else {
        Modifier.widthIn(max = 410.dp).fillMaxWidth().height(tabHeight + 10.dp)
    }
    val capsule = CircleShape
    val dockFill = remember(dark) {
        Brush.verticalGradient(if (dark) listOf(Color(0xAE465852), Color(0xCE13201D), Color(0xCF1B2C26))
            else listOf(Color(0xC9FFFFFF), Color(0xBDF1F8F5), Color(0xC8DBECE7)))
    }
    val lensFill = remember(dark) {
        Brush.linearGradient(if (dark) listOf(Color(0xC290BAB0), Color(0xAD365C53), Color(0xB8386157), Color(0xBE729D91))
            else listOf(Color(0xDEFFFFFF), Color(0xBAE1F6EC), Color(0xAFC2E9DA), Color(0xD3EEFCF5)))
    }
    val rim = if (dark) Color(0xFF76938B) else Color(0xFFB2C9C2)
    val accent = if (dark) Color(0xFFD0F4E8) else Color(0xFF103C32)
    val muted = if (dark) Color(0xFFB4C3BD) else Color(0xFF4F645C)
    Box(modifier.then(dockBounds).shadow(5.dp, capsule).clip(capsule)) {
        ReflectedBackdrop(Modifier.matchParentSize())
        Box(Modifier.matchParentSize().background(dockFill).border(1.dp, rim, capsule))
        BoxWithConstraints(
            Modifier.fillMaxSize().padding(5.dp).selectableGroup().pointerInput(rail, isRtl) {
                fun index(point: Offset): Float {
                    val length = if (rail) size.height else size.width
                    val coordinate = when {
                        rail -> point.y
                        isRtl -> length - point.x
                        else -> point.x
                    }
                    return (count * coordinate / length.coerceAtLeast(1) - .5f).coerceIn(0f, count - 1f)
                }
                detectDragGestures(
                    onDragStart = { dragPosition = index(it) },
                    onDrag = { change, _ -> change.consume(); dragPosition = index(change.position) },
                    onDragCancel = { releasePosition = dragPosition; dragPosition = null },
                    onDragEnd = {
                        val target = dragPosition?.roundToInt()
                        releasePosition = dragPosition
                        dragPosition = null
                        if (target != null) currentOnSelect(target)
                    },
                )
            },
        ) {
            val slotWidth = if (rail) maxWidth else maxWidth / count
            val slotHeight = if (rail) maxHeight / count else maxHeight
            val at = (dragPosition ?: releasePosition ?: position.value).coerceIn(0f, count - 1f)
            Box(
                Modifier.offset(if (rail) 0.dp else slotWidth * at, if (rail) slotHeight * at else 0.dp)
                    .size(slotWidth, slotHeight)
                    .graphicsLayer {
                        scaleX = if (rail) 1f else stretch
                        scaleY = if (rail) stretch else 1f
                    }.clip(capsule),
            ) {
                ReflectedBackdrop(Modifier.matchParentSize())
                Box(Modifier.matchParentSize().background(lensFill, capsule).border(1.dp, rim, capsule))
            }
            val item: @Composable (Int, Modifier) -> Unit = { i, cell ->
                val active = i == selected
                val ink = if (active) accent else muted
                Column(
                    cell.selectable(selected = active, role = Role.Tab, onClick = { currentOnSelect(i) }),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    NavGlyph(i, ink)
                    Text(destinations[i], color = ink, fontSize = 12.sp, lineHeight = 15.sp,
                        fontWeight = if (active) FontWeight.Bold else FontWeight.Medium, maxLines = 1)
                }
            }
            if (rail) Column(Modifier.fillMaxSize()) {
                destinations.indices.forEach { item(it, Modifier.fillMaxWidth().weight(1f)) }
            } else Row(Modifier.fillMaxSize()) {
                destinations.indices.forEach { item(it, Modifier.fillMaxHeight().weight(1f)) }
            }
        }
    }
}

@Composable
private fun NavGlyph(index: Int, color: Color) {
    Canvas(Modifier.size(22.dp)) {
        val stroke = Stroke(width = 1.7f, cap = StrokeCap.Round, join = StrokeJoin.Round)
        scale(size.width / 24f, size.height / 24f, pivot = Offset.Zero) {
            when (index) {
                0 -> {
                    drawRoundRect(color, Offset(3f,4f), Size(18f,16f), CornerRadius(3f), style = stroke)
                    drawLine(color, Offset(4f,10f), Offset(20f,10f), stroke.width)
                    drawLine(color, Offset(10f,10f), Offset(10f,19f), stroke.width)
                }
                1 -> {
                    drawRoundRect(color, Offset(6f,2f), Size(12f,20f), CornerRadius(3f), style = stroke)
                    drawLine(color, Offset(10f,18f), Offset(14f,18f), stroke.width, StrokeCap.Round)
                }
                else -> {
                    val outline = Path().apply {
                        moveTo(6f,3f); lineTo(18f,3f); lineTo(18f,21f); lineTo(15f,19f)
                        lineTo(12f,21f); lineTo(9f,19f); lineTo(6f,21f); close()
                    }
                    drawPath(outline, color, style = stroke)
                    drawLine(color, Offset(9f,8f), Offset(15f,8f), stroke.width, StrokeCap.Round)
                    drawLine(color, Offset(9f,12f), Offset(15f,12f), stroke.width, StrokeCap.Round)
                }
            }
        }
    }
}
