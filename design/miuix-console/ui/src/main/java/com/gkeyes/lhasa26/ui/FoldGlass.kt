package com.gkeyes.lhasa26.ui

import android.graphics.RenderEffect
import android.graphics.RuntimeShader
import androidx.compose.foundation.Canvas
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.layer.GraphicsLayer
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalView
import top.yukonga.miuix.kmp.squircle.LocalSquircleEnabled

private class GlassSource(val layer: GraphicsLayer) {
    var origin by mutableStateOf<Offset?>(null)
}
private val LocalGlassSource = staticCompositionLocalOf<GlassSource?> { null }

/** Scope the recorded content to one window; no bitmaps or pixel copies cross the GPU boundary. */
@Composable
fun FoldGlassHost(hardwareEffectsEnabled: Boolean = true, content: @Composable () -> Unit) {
    val enabled = hardwareEffectsEnabled && LocalSquircleEnabled.current && LocalView.current.isHardwareAccelerated
    val source = if (enabled) {
        val layer = rememberGraphicsLayer()
        remember(layer) { GlassSource(layer) }
    } else null
    CompositionLocalProvider(
        LocalSquircleEnabled provides enabled,
        LocalGlassSource provides source,
        content = content,
    )
}

/** Apply to the page viewport only. The overlay that samples this layer must be a sibling. */
@Composable
fun Modifier.foldGlassSource(): Modifier {
    val source = LocalGlassSource.current ?: return this
    return this.onGloballyPositioned { source.origin = it.positionInRoot() }
        .drawWithContent {
            source.layer.record { this@drawWithContent.drawContent() }
            drawLayer(source.layer)
        }
}

@Composable
internal fun ReflectedBackdrop(modifier: Modifier = Modifier) {
    val source = LocalGlassSource.current ?: return
    DrawRefractedLayer(source, modifier)
}

// Original AGSL implementation inspired by the optically thick rim of Miuix's v0.9.4
// example/shared/.../component/liquid/Lens.kt. The scene itself is never warped.
@Composable
private fun DrawRefractedLayer(source: GlassSource, modifier: Modifier) {
    var origin by remember { mutableStateOf<Offset?>(null) }
    Canvas(
        modifier.onGloballyPositioned { origin = it.positionInRoot() }
            .drawWithCache {
                val effect = lensEffect(size, 12f * density)
                val layer = obtainGraphicsLayer().apply { renderEffect = effect.asComposeRenderEffect() }
                onDrawBehind {
                    val local = origin ?: return@onDrawBehind
                    val content = source.origin ?: return@onDrawBehind
                    val offset = content - local
                    layer.record {
                        translate(offset.x, offset.y) { drawLayer(source.layer) }
                    }
                    drawLayer(layer)
                }
            },
    ) {}
}

private fun lensEffect(size: Size, maxRim: Float): RenderEffect {
    val shader = RuntimeShader(
        """
        uniform shader page;
        uniform float2 extent;
        uniform float rim;
        half4 main(float2 p) {
            float2 center = extent * 0.5;
            float radius = min(center.x, center.y);
            float2 a = p - center;
            float2 axial = max(center - radius, float2(0.0));
            float2 n = a - clamp(a, -axial, axial);
            float len = length(n);
            float edge = clamp(1.0 - (radius-len) / rim, 0.0, 1.0);
            float2 ray = n / max(len, 0.001) * (edge * edge * rim * 0.85);
            float2 uv = clamp(p - ray, float2(0.5), extent - 0.5);
            return page.eval(uv);
        }
        """.trimIndent(),
    )
    shader.setFloatUniform("extent", size.width.coerceAtLeast(1f), size.height.coerceAtLeast(1f))
    shader.setFloatUniform("rim", maxRim.coerceAtLeast(1f))
    return RenderEffect.createRuntimeShaderEffect(shader, "page")
}
