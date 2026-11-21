package com.gkeyes.lhasa26.ui;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.PixelFormat;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;

/** Rounded glass surfaces drawn directly over the window's solid background. */
public final class GlassMaterial {
    public enum Layer { HERO, CARD, INSET, BUTTON }

    private static final Shader.TileMode CLAMP = Shader.TileMode.CLAMP;
    private final float density;
    private final boolean dark;

    public GlassMaterial(float density, boolean dark) {
        this.density = density;
        this.dark = dark;
    }

    public Drawable surface(Layer layer, float radiusDp) {
        return new Surface(layer, radiusDp * density);
    }

    private final class Surface extends Drawable {
        final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.DITHER_FLAG);
        final Layer layer;
        final float radius;
        final RectF face = new RectF();
        final RectF edge = new RectF();
        Shader wash, rim;

        Surface(Layer layer, float radius) {
            this.layer = layer;
            this.radius = radius;
        }

        @Override protected void onBoundsChange(Rect bounds) {
            face.set(bounds);
            float stroke = Math.max(1f, density);
            edge.set(face);
            edge.inset(stroke / 2f, stroke / 2f);
            if (face.isEmpty()) return;
            int top, bottom;
            if (layer == Layer.BUTTON) {
                top = dark ? 0xa5325265 : 0xb3f2ffff;
                bottom = dark ? 0x8c1f3e4f : 0x85e2f7fa;
            } else if (layer == Layer.INSET) {
                top = dark ? 0x901d3044 : 0x73f3f8fa;
                bottom = dark ? 0x7a192f40 : 0x60deeff3;
            } else {
                top = dark ? 0x7d254253 : 0x7df4fafd;
                bottom = dark ? 0x69102a39 : 0x52e4f1f7;
            }
            wash = new LinearGradient(face.left, face.top, face.right, face.bottom, top, bottom, CLAMP);
            int[] edges = dark ? new int[]{0x98dcf9ff, 0x40c0e3ed, 0x995da3b9}
                               : new int[]{0xfaffffff, 0xbbffffff, 0xd1b9dee9};
            if (layer == Layer.BUTTON || layer == Layer.INSET) {
                edges = dark ? new int[]{0x7aa6d6e3, 0x335a899d, 0x6693bac7}
                             : new int[]{0x705f9baf, 0x305c8a97, 0x4382afbb};
            }
            rim = new LinearGradient(face.left, face.top, face.left + face.width() * .23f,
                    face.bottom, edges, new float[]{0f, .58f, 1f}, CLAMP);
        }

        @Override public void draw(Canvas c) {
            if (face.isEmpty()) return;
            paint.setStyle(Paint.Style.FILL);
            paint.setShader(wash);
            c.drawRoundRect(face, radius, radius, paint);
            float stroke = Math.max(1f, density);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(stroke);
            paint.setShader(rim);
            float edgeRadius = Math.max(0f, radius - stroke / 2f);
            c.drawRoundRect(edge, edgeRadius, edgeRadius, paint);
            paint.setStyle(Paint.Style.FILL);
        }

        @Override public void setAlpha(int alpha) { paint.setAlpha(alpha); invalidateSelf(); }
        @Override public void setColorFilter(ColorFilter filter) { paint.setColorFilter(filter); invalidateSelf(); }
        @Override public int getOpacity() { return PixelFormat.TRANSLUCENT; }
        @Override public void getOutline(Outline outline) { outline.setRoundRect(getBounds(), radius); }
    }
}
