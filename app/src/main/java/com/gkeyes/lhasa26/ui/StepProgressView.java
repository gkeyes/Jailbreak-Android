package com.gkeyes.lhasa26.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.View;

public final class StepProgressView extends View {
    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final int fillColor;
    private final int trackColor;
    private float ratio;

    public StepProgressView(Context context, int fillColor, int trackColor) {
        super(context);
        this.fillColor = fillColor;
        this.trackColor = trackColor;
        setWillNotDraw(false);
    }

    public void setRatio(float ratio) {
        this.ratio = Math.max(0f, Math.min(1f, ratio));
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float height = getHeight();
        float radius = height / 2f;
        paint.setColor(trackColor);
        canvas.drawRoundRect(0, 0, getWidth(), height, radius, radius, paint);
        if (ratio > 0f) {
            paint.setColor(fillColor);
            float width = Math.max(height, getWidth() * ratio);
            canvas.drawRoundRect(0, 0, width, height, radius, radius, paint);
        }
    }
}
