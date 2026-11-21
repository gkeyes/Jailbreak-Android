package com.gkeyes.lhasa26.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.View;

public final class StepProgressView extends View {
    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private float ratio;

    public StepProgressView(Context context) {
        super(context);
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
        paint.setColor(0x558C9AB3);
        canvas.drawRoundRect(0, 0, getWidth(), height, radius, radius, paint);
        if (ratio > 0f) {
            paint.setColor(0xFFFFFFFF);
            float width = Math.max(height, getWidth() * ratio);
            canvas.drawRoundRect(0, 0, width, height, radius, radius, paint);
        }
    }
}
