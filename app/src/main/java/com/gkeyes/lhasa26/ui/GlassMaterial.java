package com.gkeyes.lhasa26.ui;

import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Matrix;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PixelFormat;
import android.graphics.RadialGradient;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.ViewTreeObserver;

import java.lang.ref.WeakReference;
import java.util.ArrayList;

/** Shared, screen-aligned glass for a fixed viewport and the cards scrolling over it. */
public final class GlassMaterial {
    public enum Layer { HERO, CARD, INSET, BUTTON }

    private static final Shader.TileMode CLAMP = Shader.TileMode.CLAMP;
    private final View viewport;
    private final boolean dark;
    private final float density;
    private final ArrayList<WeakReference<View>> owners = new ArrayList<>();
    private final ViewTreeObserver.OnScrollChangedListener scrollListener = this::invalidateSurfaces;
    private ViewTreeObserver observer;
    private Bitmap sharp;
    private Bitmap soft;
    private int sceneWidth;
    private int sceneHeight;

    public GlassMaterial(View viewport, boolean dark) {
        this.viewport = viewport;
        this.dark = dark;
        density = viewport.getResources().getDisplayMetrics().density;
        viewport.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() {
            @Override public void onViewAttachedToWindow(View view) { observeScroll(); }
            @Override public void onViewDetachedFromWindow(View view) {
                if (observer != null && observer.isAlive()) {
                    observer.removeOnScrollChangedListener(scrollListener);
                }
                observer = null;
            }
        });
        viewport.addOnLayoutChangeListener((v, l, t, r, b, oldL, oldT, oldR, oldB) -> {
            if (l != oldL || t != oldT || r != oldR || b != oldB) invalidateSurfaces();
        });
        if (viewport.isAttachedToWindow()) observeScroll();
    }

    private void observeScroll() {
        observer = viewport.getViewTreeObserver();
        observer.addOnScrollChangedListener(scrollListener);
    }

    public Drawable backdrop() {
        return new Coating() {
            @Override public void draw(Canvas canvas) {
                if (prepareScene()) canvas.drawBitmap(sharp, null, getBounds(), paint);
            }
        };
    }

    /** BUTTON and INSET are translucent over their parent panel. */
    public Drawable surface(View owner, Layer layer, float radiusDp) {
        if (layer == Layer.CARD || layer == Layer.HERO) {
            boolean registered = false;
            for (WeakReference<View> entry : owners) {
                if (entry.get() == owner) { registered = true; break; }
            }
            if (!registered) owners.add(new WeakReference<>(owner));
        }
        return new Surface(owner, layer, radiusDp * density);
    }

    public void invalidateSurfaces() {
        for (int i = owners.size() - 1; i >= 0; --i) {
            View owner = owners.get(i).get();
            if (owner == null) owners.remove(i);
            else if (owner.isShown()) owner.invalidate();
        }
    }

    private boolean prepareScene() {
        int width = viewport.getWidth();
        int height = viewport.getHeight();
        if (width <= 0 || height <= 0) return false;
        if (sceneWidth == width && sceneHeight == height && soft != null) return true;
        float scale = Math.min(1f, 512f / Math.max(width, height));
        int w = Math.max(1, Math.round(width * scale));
        int h = Math.max(1, Math.round(height * scale));
        sharp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
        sharp.setDensity(Bitmap.DENSITY_NONE);
        Canvas canvas = new Canvas(sharp);
        Paint p = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.DITHER_FLAG);
        p.setShader(new LinearGradient(0f, 0f, w * .58f, h,
                dark ? new int[]{0xff101e2c, 0xff081b29, 0xff0c192a}
                     : new int[]{0xffe2ebf2, 0xffd8e9f0, 0xffe4ecf0},
                null, CLAMP));
        canvas.drawRect(0f, 0f, w, h, p);
        glow(canvas, p, w * .78f, h * .12f, w * .84f, h * .56f,
                dark ? 0xad183e51 : 0xebffffff);
        glow(canvas, p, w * (dark ? .76f : .08f), h * .79f, w * .85f, h * .61f,
                dark ? 0xf21e304a : 0xf0d0e1ec);
        ribbon(canvas, p, w, h, false);
        ribbon(canvas, p, w, h, true);
        soft = blurred(sharp, Math.max(1, Math.round(12f * density * scale)));
        sceneWidth = width;
        sceneHeight = height;
        return true;
    }

    private static void glow(Canvas canvas, Paint paint, float x, float y,
                             float rx, float ry, int color) {
        canvas.save();
        canvas.translate(x, y);
        canvas.scale(rx, ry);
        paint.setShader(new RadialGradient(0f, 0f, 1f, color, color & 0x00ffffff, CLAMP));
        canvas.drawCircle(0f, 0f, 1f, paint);
        canvas.restore();
    }

    private void ribbon(Canvas c, Paint p, int w, int h, boolean reflection) {
        float top = h * (reflection ? .402f : .37f);
        float bandHeight = h * (reflection ? .124f : .17f);
        float left = -.46f * w;
        float right = 1.59f * w;
        float bandWidth = right - left;
        RectF bounds = new RectF(left, top, right, top + bandHeight);
        c.save();
        c.rotate(reflection ? -24f : -29f, bounds.centerX(), bounds.centerY());
        int[] colors;
        float[] stops;
        if (reflection) {
            colors = dark ? new int[]{0x6971f8e8, 0x1f18b3be, 0x144488bf, 0x346fb3d0}
                          : new int[]{0x6ff1ffff, 0x29befcf9, 0x248bdcf9, 0x41d1f0ff};
            stops = new float[]{0f, .16f, .81f, 1f};
        } else {
            colors = dark ? new int[]{0x2473fcea, 0xff49d9cc, 0xff1397a0, 0xff137a9f, 0xff1a608a, 0x524b97bd}
                          : new int[]{0x52bbfdf0, 0xff81e4dc, 0xff3bc3c6, 0xff57c3d9, 0xffb2d8f5, 0x3dbee2f8};
            stops = new float[]{0f, .05f, .25f, .65f, .94f, 1f};
        }
        p.setShader(new LinearGradient(0f, top, 0f, top + bandHeight, colors, stops, CLAMP));
        Path path = new Path();
        path.addRoundRect(bounds, new float[]{
                .61f * bandWidth, .56f * bandHeight, .39f * bandWidth, .35f * bandHeight,
                .38f * bandWidth, .65f * bandHeight, .62f * bandWidth, .44f * bandHeight
        }, Path.Direction.CW);
        c.drawPath(path, p);
        c.restore();
    }

    /** Separable blur runs once per viewport size, regardless of how many cards it contains. */
    private static Bitmap blurred(Bitmap source, int radius) {
        int w = source.getWidth(), h = source.getHeight();
        int[] pixels = new int[w * h];
        int[] scratch = new int[pixels.length];
        source.getPixels(pixels, 0, w, 0, 0, w, h);
        // Two box passes approximate a Gaussian with a softer falloff than a single box.
        for (int pass = 0; pass < 2; pass++) {
            for (int y = 0; y < h; y++) blurLine(pixels, scratch, y * w, 1, w, radius);
            for (int x = 0; x < w; x++) blurLine(scratch, pixels, x, w, h, radius);
        }
        Bitmap result = Bitmap.createBitmap(pixels, w, h, Bitmap.Config.ARGB_8888);
        result.setDensity(Bitmap.DENSITY_NONE);
        return result;
    }

    private static void blurLine(int[] input, int[] output, int start, int stride,
                                 int length, int radius) {
        int r = 0, g = 0, b = 0;
        int count = radius * 2 + 1;
        for (int i = -radius; i <= radius; i++) {
            int color = input[start + Math.max(0, Math.min(length - 1, i)) * stride];
            r += (color >>> 16) & 255; g += (color >>> 8) & 255; b += color & 255;
        }
        for (int i = 0; i < length; i++) {
            output[start + i * stride] = 0xff000000 | ((r / count) << 16) | ((g / count) << 8) | b / count;
            int old = input[start + Math.max(0, i - radius) * stride];
            int next = input[start + Math.min(length - 1, i + radius + 1) * stride];
            r += ((next >>> 16) & 255) - ((old >>> 16) & 255);
            g += ((next >>> 8) & 255) - ((old >>> 8) & 255);
            b += (next & 255) - (old & 255);
        }
    }

    private abstract static class Coating extends Drawable {
        final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG | Paint.DITHER_FLAG);
        @Override public void setAlpha(int alpha) { paint.setAlpha(alpha); invalidateSelf(); }
        @Override public void setColorFilter(ColorFilter filter) { paint.setColorFilter(filter); invalidateSelf(); }
        @Override public int getOpacity() { return PixelFormat.TRANSLUCENT; }
    }

    private final class Surface extends Coating {
        final View owner;
        final Layer layer;
        final float radius;
        final RectF face = new RectF();
        final RectF edge = new RectF();
        final Matrix mapping = new Matrix();
        final int[] anchor = new int[2], position = new int[2];
        Bitmap sampled;
        BitmapShader lens;
        Shader wash, rim;

        Surface(View owner, Layer layer, float radius) {
            this.owner = owner;
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
            if ((layer == Layer.CARD || layer == Layer.HERO) && prepareScene()) {
                if (sampled != soft) {
                    sampled = soft;
                    lens = new BitmapShader(soft, CLAMP, CLAMP);
                }
                viewport.getLocationInWindow(anchor);
                owner.getLocationInWindow(position);
                float x = position[0] - anchor[0], y = position[1] - anchor[1];
                float zoom = layer == Layer.HERO ? 1.043f : 1.027f;
                mapping.setScale(zoom * sceneWidth / soft.getWidth(), zoom * sceneHeight / soft.getHeight());
                // Scale about the centre of this panel in viewport coordinates.
                mapping.postTranslate(-zoom * x + (1f - zoom) * face.centerX(),
                        -zoom * y + (1f - zoom) * face.centerY());
                lens.setLocalMatrix(mapping);
                paint.setShader(lens);
                c.drawRoundRect(face, radius, radius, paint);
            }
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

        @Override public void getOutline(Outline outline) { outline.setRoundRect(getBounds(), radius); }
    }
}
