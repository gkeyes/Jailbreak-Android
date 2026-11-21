package com.gkeyes.lhasa26.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.unit.dp

/** A quiet satin glass face with a turned, translucent edge. Children own input and padding. */
@Composable
internal fun FoldStatusGlass(
    modifier: Modifier = Modifier,
    dark: Boolean,
    content: @Composable ColumnScope.() -> Unit,
) {
    val radius = 26.dp
    Column(
        modifier.clip(RoundedCornerShape(radius)).drawWithCache {
            if (size.width < 2f || size.height < 2f) return@drawWithCache onDrawWithContent { drawContent() }
            val rimWidth = 1.dp.toPx().coerceAtMost(size.minDimension / 3)
            val rimInset = rimWidth / 2
            val rimSize = Size(size.width - rimWidth, size.height - rimWidth)
            val rimRadius = CornerRadius((radius.toPx() - rimInset).coerceAtLeast(0f))
            val rimOffset = Offset(rimInset, rimInset)
            val rimStroke = Stroke(rimWidth)
            val face = Brush.linearGradient(
                colors = if (dark) listOf(Color(0xFF101C19), Color(0xFF101815), Color(0xFF192320))
                         else listOf(Color(0xFFF6FCFA), Color(0xFFE8F2ED), Color(0xFFF0F7F4)),
                start = Offset.Zero, end = Offset(size.width, size.height),
            )
            val rim = Brush.linearGradient(
                colors = if (dark) listOf(Color(0xFF638278), Color(0xFF34483F), Color(0xFF4F665E))
                         else listOf(Color(0xFFBCCFC6), Color(0xFFD4E0D9), Color(0xFFA3BDB2)),
                start = Offset.Zero, end = Offset(size.width * .78f, size.height),
            )

            // Draw the fold using a single, uniformly scaled local coordinate system.
            val artScale = minOf(size.width * .38f / 180f, size.height * .72f / 142f, 1.16.dp.toPx())
            val left = size.width - 181f * artScale - 7.dp.toPx()
            val top = minOf(22.dp.toPx(), size.height * .11f)
            val silver = if (dark) Color(0xFFABCEC0) else Color.White
            val milk = if (dark) Color(0xFF759B90) else Color(0xFFBAE4D8)
            val teal = if (dark) Color(0xFF456B61) else Color(0xFF78BCB0)
            val deep = if (dark) Color(0xFF2C433E) else Color(0xFF466A64)

            val foldBack = Path().apply {
                moveTo(34f, 127f)
                cubicTo(29f, 111f, 59f, 56f, 103f, 25f)
                cubicTo(125f, 9f, 153f, 1f, 165f, 14f)
                cubicTo(176f, 27f, 160f, 61f, 139f, 83f)
                lineTo(130f, 77f)
                cubicTo(145f, 60f, 162f, 31f, 153f, 24f)
                cubicTo(144f, 15f, 121f, 26f, 103f, 40f)
                cubicTo(75f, 62f, 45f, 106f, 48f, 118f)
                cubicTo(54f, 128f, 99f, 104f, 129f, 78f)
                lineTo(141f, 84f)
                cubicTo(110f, 114f, 45f, 153f, 34f, 127f)
                close()
            }
            val foldFront = Path().apply {
                moveTo(11f, 125f)
                cubicTo(30f, 137f, 62f, 113f, 87f, 89f)
                cubicTo(113f, 62f, 142f, 23f, 149f, 14f)
                cubicTo(152f, 10f, 155f, 9f, 158f, 9f)
                cubicTo(139f, 5f, 112f, 20f, 92f, 40f)
                cubicTo(76f, 55f, 60f, 76f, 45f, 95f)
                cubicTo(30f, 113f, 22f, 120f, 11f, 125f)
                close()
            }
            val bevel = Path().apply {
                moveTo(11f, 125f)
                cubicTo(30f, 137f, 62f, 113f, 87f, 89f)
                cubicTo(113f, 62f, 142f, 23f, 149f, 14f)
                cubicTo(153f, 8f, 157f, 8f, 162f, 12f)
                lineTo(167f, 18f)
                cubicTo(158f, 13f, 155f, 21f, 150f, 29f)
                cubicTo(133f, 55f, 110f, 82f, 90f, 101f)
                cubicTo(63f, 126f, 27f, 147f, 16f, 133f)
                close()
            }
            val glint = Path().apply {
                moveTo(16f, 127f)
                cubicTo(34f, 135f, 65f, 111f, 87f, 89f)
                cubicTo(111f, 65f, 131f, 39f, 148f, 15f)
                moveTo(149f, 10f)
                cubicTo(158f, 7f, 165f, 12f, 167f, 18f)
            }

            val back = Brush.linearGradient(
                0f to silver.copy(alpha = .65f), .18f to milk.copy(alpha = .25f),
                .52f to teal.copy(alpha = .23f), .73f to silver.copy(alpha = .66f),
                .88f to deep.copy(alpha = .51f), 1f to milk.copy(alpha = .32f),
                start = Offset(79f, 13f), end = Offset(148f, 103f),
            )
            val front = Brush.linearGradient(
                0f to teal.copy(alpha = .53f), .14f to silver.copy(alpha = .82f),
                .31f to milk.copy(alpha = .25f), .5f to silver.copy(alpha = .12f),
                .76f to teal.copy(alpha = .43f), .86f to deep.copy(alpha = .58f),
                .95f to silver.copy(alpha = .78f), 1f to teal.copy(alpha = .45f),
                start = Offset(60f, 16f), end = Offset(143f, 99f),
            )
            val edge = Brush.linearGradient(
                0f to teal.copy(alpha = .5f), .2f to silver.copy(alpha = .85f),
                .41f to milk.copy(alpha = .5f), .56f to deep.copy(alpha = .67f),
                .68f to silver.copy(alpha = .82f), 1f to milk.copy(alpha = .5f),
                start = Offset(37f, 135f), end = Offset(144f, 20f),
            )
            val sparkle = Brush.linearGradient(
                0f to silver.copy(alpha = .18f), .18f to silver.copy(alpha = .85f),
                .48f to milk.copy(alpha = .26f), .83f to silver.copy(alpha = .9f),
                1f to silver.copy(alpha = .15f),
                start = Offset(10f, 129f), end = Offset(166f, 15f),
            )
            val fineStroke = Stroke(width = 1.12f, cap = StrokeCap.Round)
            val poolCenter = Offset(left + 111f * artScale, top + 97f * artScale)
            val poolRadius = 68f * artScale
            val pool = Brush.radialGradient(
                listOf(milk.copy(alpha = if (dark) .12f else .25f), milk.copy(alpha = 0f)),
                center = poolCenter, radius = poolRadius,
            )
            onDrawWithContent {
                drawRect(face)
                drawCircle(pool, radius = poolRadius, center = poolCenter)
                withTransform({
                    translate(left, top)
                    scale(artScale, artScale, Offset.Zero)
                }) {
                    drawPath(foldBack, back)
                    drawPath(foldFront, front)
                    drawPath(bevel, edge)
                    drawPath(glint, sparkle, style = fineStroke)
                }
                drawRoundRect(rim, rimOffset, rimSize, rimRadius, style = rimStroke)
                drawContent()
            }
        },
        content = content,
    )
}
