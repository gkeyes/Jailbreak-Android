package com.gkeyes.lhasa26.ui

import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.PressInteraction
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.unit.dp
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun FoldActionButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    primary: Boolean = false,
) {
    val dark = MiuixTheme.colorScheme.background.luminance() < .15f
    val interactions = remember { MutableInteractionSource() }
    var press by remember { mutableStateOf<PressInteraction.Press?>(null) }
    LaunchedEffect(interactions) {
        interactions.interactions.collect { event ->
            when (event) {
                is PressInteraction.Press -> press = event
                is PressInteraction.Release -> if (press === event.press) press = null
                is PressInteraction.Cancel -> if (press === event.press) press = null
            }
        }
    }
    val textInk = if (!primary) MiuixTheme.colorScheme.onSurface
                  else if (dark) Color(0xFF0A2B22) else Color.White
    val disabledInk = if (dark) Color(0xFFD0DCD6) else Color(0xFF43544D)
    val radius = if (primary) 16.dp else 15.dp
    TextButton(
        text = text,
        onClick = onClick,
        modifier = modifier.clip(RoundedCornerShape(radius)).drawWithCache {
            if (size.minDimension < 2f) return@drawWithCache onDrawBehind {}
            val colors = when {
                !enabled && dark -> listOf(Color(0xFF36413B), Color(0xFF2A322E), Color(0xFF303A35))
                !enabled -> listOf(Color(0xFFE2E7E4), Color(0xFFD3DBD6), Color(0xFFDBE2DE))
                primary && dark -> listOf(Color(0xFFB5E7D6), Color(0xFF83BFAA), Color(0xFFA4D7C6))
                primary -> listOf(Color(0xFF39796D), Color(0xFF115448), Color(0xFF2A695C))
                dark -> listOf(Color(0xFF30443D), Color(0xFF16201C), Color(0xFF273731))
                else -> listOf(Color(0xFFEBF4F0), Color(0xFFF8FBF9), Color(0xFFDBE8E1))
            }
            val face = Brush.linearGradient(
                colors, start = Offset(size.width * .16f, 0f), end = Offset(size.width * .18f, size.height),
            )
            val rimColor = when {
                primary && enabled && dark -> Color(0xFFA6D3C1)
                primary && enabled -> Color(0xFF387766)
                dark -> Color(0xFF596A60)
                else -> Color(0xFFAEBCB5)
            }
            val rimWidth = 1.dp.toPx().coerceAtMost(size.minDimension / 3)
            val inset = rimWidth / 2
            val outerSize = Size(size.width - rimWidth, size.height - rimWidth)
            val outerTop = Offset(inset, inset)
            val outerRadius = CornerRadius((radius.toPx() - inset).coerceAtLeast(0f))
            val stroke = Stroke(rimWidth)
            val refraction = Brush.verticalGradient(
                0f to Color.White.copy(alpha = if (enabled) .71f else .24f),
                .07f to Color.White.copy(alpha = if (enabled) .18f else .03f),
                .24f to Color.Transparent, .78f to Color.Transparent,
                .96f to Color(0xFFB9F5D8).copy(alpha = if (enabled) .17f else .03f),
                1f to rimColor.copy(alpha = .65f),
                startY = rimWidth, endY = size.height - rimWidth,
            )
            val touch = if (enabled) press?.pressPosition else null
            // A ridge of light near the point of contact. The centre stays readable.
            val lightX = if (touch != null && touch.x.isFinite()) touch.x.coerceIn(0f, size.width)
                         else size.width * .24f
            val lightCenter = Offset(lightX, if (touch == null) -size.height * .53f else -size.height * .16f)
            val glint = Brush.radialGradient(
                listOf(Color.White.copy(alpha = if (!enabled) .03f else if (touch == null) .12f else .22f),
                    Color.Transparent),
                center = lightCenter, radius = size.height * 1.6f,
            )
            onDrawBehind {
                drawRect(face)
                drawRect(refraction)
                drawRect(glint)
                drawRoundRect(rimColor, outerTop, outerSize, outerRadius, style = stroke)
            }
        },
        enabled = enabled,
        minHeight = if (primary) 50.dp else 48.dp,
        cornerRadius = radius,
        interactionSource = interactions,
        colors = ButtonDefaults.textButtonColors(
            color = Color.Transparent,
            disabledColor = Color.Transparent,
            textColor = textInk,
            disabledTextColor = disabledInk,
        ),
    )
}
