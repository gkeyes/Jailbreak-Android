package com.gkeyes.lhasa26;

import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.InputStream;

public final class DonateActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(0xFFF2F1F7);
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(18), statusBarHeight() + dp(12), dp(18), navBarHeight() + dp(20));
        content.setBackgroundColor(0xFFF2F1F7);

        TextView back = text("‹  返回", 15, 0xFF3478F6, false);
        back.setPadding(0, 0, 0, dp(10));
        back.setOnClickListener(v -> finish());
        content.addView(back);

        TextView title = text("捐赠", 30, 0xFF1F2026, true);
        title.setPadding(0, dp(6), 0, 0);
        content.addView(title);
        TextView subtitle = text("感谢支持 · Lhasa26-Android", 13, 0xFF8A8994, false);
        subtitle.setPadding(0, dp(8), 0, 0);
        content.addView(subtitle);

        LinearLayout imageCard = new LinearLayout(this);
        imageCard.setPadding(dp(10), dp(10), dp(10), dp(10));
        imageCard.setBackground(round(0xFFFFFFFF, 26));
        LinearLayout.LayoutParams imageCardParams = new LinearLayout.LayoutParams(-1, -2);
        imageCardParams.topMargin = dp(18);
        imageCard.setLayoutParams(imageCardParams);
        ImageView image = new ImageView(this);
        image.setAdjustViewBounds(true);
        image.setScaleType(ImageView.ScaleType.FIT_CENTER);
        imageCard.addView(image, new LinearLayout.LayoutParams(-1, -2));
        content.addView(imageCard);

        TextView hint = text("若本工具对您有所帮助，可通过扫码给予支持。", 12, 0xFF8A8994, false);
        hint.setPadding(dp(4), dp(16), dp(4), 0);
        content.addView(hint);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(content);
        setContentView(scroll);
        loadImage(image);
    }

    private void loadImage(ImageView image) {
        new Thread(() -> {
            try (InputStream input = getAssets().open("donate.jpg")) {
                Bitmap bitmap = BitmapFactory.decodeStream(input);
                runOnUiThread(() -> image.setImageBitmap(bitmap));
            } catch (Exception ignored) {
            }
        }, "lhasa-donate-image").start();
    }

    private TextView text(String value, float size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        if (bold) {
            view.setTypeface(Typeface.DEFAULT_BOLD);
        }
        return view;
    }

    private GradientDrawable round(int color, int radius) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(radius));
        return drawable;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private int statusBarHeight() {
        int id = getResources().getIdentifier("status_bar_height", "dimen", "android");
        return id > 0 ? getResources().getDimensionPixelSize(id) : dp(28);
    }

    private int navBarHeight() {
        int id = getResources().getIdentifier("navigation_bar_height", "dimen", "android");
        return id > 0 ? getResources().getDimensionPixelSize(id) : dp(24);
    }
}
