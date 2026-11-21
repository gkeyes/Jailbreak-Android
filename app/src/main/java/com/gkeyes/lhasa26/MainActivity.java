package com.gkeyes.lhasa26;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.StateListDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.provider.MediaStore;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import com.gkeyes.lhasa26.core.CommandResult;
import com.gkeyes.lhasa26.core.DeviceSnapshot;
import com.gkeyes.lhasa26.core.ShizukuExecutor;
import com.gkeyes.lhasa26.core.WorkflowCallbacks;
import com.gkeyes.lhasa26.core.WorkflowEngine;
import com.gkeyes.lhasa26.ui.GlassMaterial;
import com.gkeyes.lhasa26.ui.StepProgressView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import rikka.shizuku.Shizuku;

public final class MainActivity extends Activity implements WorkflowCallbacks {
    private static final int REQUEST_SHIZUKU = 1001;
    private boolean dark;
    private int ink;
    private int muted;
    private int accent;
    private int line;
    private int success;
    private int danger;
    private GlassMaterial glass;
    private SharedPreferences preferences;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ShizukuExecutor executor = new ShizukuExecutor();
    private final Shizuku.OnBinderReceivedListener binderReceived = this::refreshConnection;
    private final Shizuku.OnBinderDeadListener binderDead = this::refreshConnection;
    private final Shizuku.OnRequestPermissionResultListener permissionResult = (requestCode, grantResult) -> {
        if (requestCode == REQUEST_SHIZUKU) refreshConnection();
    };
    private WorkflowEngine engine;
    private long startAt;
    private boolean timing;

    private LinearLayout root;
    private View statusRing;
    private LinearLayout progressDetails;
    private TextView shizukuState;
    private TextView privilegeState;
    private TextView emptyLog;
    private TextView status;
    private TextView stepLabel;
    private TextView timer;
    private TextView log;
    private TextView deviceValue;
    private TextView buildValue;
    private TextView kernelValue;
    private TextView fitValue;
    private Button action;
    private Button diagnose;
    private Button authorization;
    private ProgressBar spinner;
    private StepProgressView stepProgress;
    private ScrollView scroll;

    private final Runnable timerTicker = new Runnable() {
        @Override
        public void run() {
            if (!timing) {
                return;
            }
            if (hasWindowFocus()) {
                timer.setText("用时 " + elapsedText(SystemClock.elapsedRealtime() - startAt));
            }
            mainHandler.postDelayed(this, 250L);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        ink = getColor(R.color.ink);
        muted = getColor(R.color.sub);
        accent = getColor(R.color.accent);
        line = getColor(R.color.line);
        success = getColor(R.color.success);
        danger = getColor(R.color.danger);
        preferences = getSharedPreferences("lhasa26", MODE_PRIVATE);
        applyKeepScreenOn(preferences.getBoolean("keep_screen_on", true));
        configureWindow(getWindow());
        engine = new WorkflowEngine(getAssets(), executor, this);
        buildUi();
        registerShizukuCallbacks();
        refreshConnection();
    }

    private void configureWindow(Window window) {
        View decor = window.getDecorView();
        if (Build.VERSION.SDK_INT >= 30) {
            window.setDecorFitsSystemWindows(false);
            WindowInsetsController controller = window.getInsetsController();
            if (controller != null) {
                int flags = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                        | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
                controller.setSystemBarsAppearance(dark ? 0 : flags, flags);
            }
        } else {
            int layout = View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                    | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION;
            int lightBars = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
            decor.setSystemUiVisibility(dark ? layout : layout | lightBars);
        }
        window.setStatusBarColor(Color.TRANSPARENT);
        window.setNavigationBarColor(Color.TRANSPARENT);
    }

    private void buildUi() {
        FrameLayout viewport = new FrameLayout(this);
        glass = new GlassMaterial(getResources().getDisplayMetrics().density, dark);
        viewport.setBackgroundColor(getColor(R.color.surface));
        scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        scroll.setVerticalScrollBarEnabled(false);
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                Insets safe = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                view.setPadding(safe.left, safe.top, safe.right, safe.bottom);
            } else {
                view.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                        insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            }
            return insets;
        });
        viewport.addView(scroll, new FrameLayout.LayoutParams(-1, -1));

        FrameLayout page = new FrameLayout(this);
        root = new LinearLayout(this) {
            @Override
            protected void onMeasure(int widthSpec, int heightSpec) {
                int width = Math.min(MeasureSpec.getSize(widthSpec), dp(520));
                super.onMeasure(MeasureSpec.makeMeasureSpec(width, MeasureSpec.EXACTLY), heightSpec);
            }
        };
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(10), dp(16), dp(20));
        page.addView(root, new FrameLayout.LayoutParams(-1, -2, Gravity.TOP | Gravity.CENTER_HORIZONTAL));
        scroll.addView(page, new ScrollView.LayoutParams(-1, -2));

        LinearLayout header = horizontalRow();
        TextView title = text(getString(R.string.app_name), 31, ink, true);
        if (Build.VERSION.SDK_INT >= 28) title.setAccessibilityHeading(true);
        header.addView(title, new LinearLayout.LayoutParams(0, -2, 1f));
        header.addView(iconButton(R.drawable.ic_settings, "设置", this::showSettings),
                new LinearLayout.LayoutParams(dp(44), dp(44)));
        root.addView(header);

        buildHero();
        buildDeviceCard();
        buildLogCard();
        buildMaintenanceCard();

        TextView help = text("在状态卡查看 Shizuku 和临时 ROOT 的状态。接口诊断可查看设备信息，日志可从运行记录导出。",
                14, muted, false);
        help.setPadding(0, 0, 0, dp(12));
        root.addView(collapsible("使用帮助", help));
        setContentView(viewport);
        scroll.requestApplyInsets();
    }

    private void buildHero() {
        LinearLayout hero = card(GlassMaterial.Layer.HERO, 20, 16);
        hero.addView(heading("设备状态"));

        LinearLayout statusRow = horizontalRow();
        statusRow.setPadding(0, dp(8), 0, dp(8));
        statusRing = new View(this);
        setHero(muted);
        LinearLayout.LayoutParams ringParams = new LinearLayout.LayoutParams(dp(18), dp(18));
        ringParams.setMarginEnd(dp(9));
        statusRow.addView(statusRing, ringParams);
        status = text("正在检测", 25, ink, true);
        status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        statusRow.addView(status, new LinearLayout.LayoutParams(0, -2, 1f));
        spinner = new ProgressBar(this);
        spinner.setIndeterminateTintList(ColorStateList.valueOf(accent));
        spinner.setVisibility(View.GONE);
        statusRow.addView(spinner, new LinearLayout.LayoutParams(dp(22), dp(22)));
        hero.addView(statusRow);

        LinearLayout metrics = horizontalRow();
        shizukuState = text("检测中", 12, ink, true);
        privilegeState = text("未知", 12, ink, true);
        metrics.addView(statusMetric("Shizuku", shizukuState), flatParams(0, 0));
        metrics.addView(statusMetric("临时 ROOT", privilegeState), flatParams(1, 6));
        hero.addView(metrics);

        authorization = button("Shizuku 授权", false);
        authorization.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
        authorization.setPaddingRelative(dp(14), dp(7), dp(14), dp(7));
        authorization.setOnClickListener(view -> {
            if (ensureShizuku()) toast("Shizuku 已授权");
        });
        LinearLayout.LayoutParams authorizationParams = new LinearLayout.LayoutParams(-1, -2);
        authorizationParams.topMargin = dp(10);
        authorizationParams.bottomMargin = dp(10);
        hero.addView(authorization, authorizationParams);

        LinearLayout buttons = horizontalRow();
        action = button("一键临时 ROOT", true);
        action.setOnClickListener(view -> onAction());
        diagnose = button("接口诊断", false);
        diagnose.setOnClickListener(view -> onDiagnose());
        buttons.addView(action, flatParams(0, 0));
        buttons.addView(diagnose, flatParams(1, 8));
        hero.addView(buttons);

        progressDetails = new LinearLayout(this);
        progressDetails.setOrientation(LinearLayout.VERTICAL);
        progressDetails.setPadding(0, dp(12), 0, 0);
        progressDetails.setVisibility(View.GONE);
        LinearLayout progressRow = horizontalRow();
        stepLabel = text("准备就绪", 12, muted, false);
        progressRow.addView(stepLabel, new LinearLayout.LayoutParams(0, -2, 1f));
        timer = text("", 12, muted, false);
        timer.setGravity(Gravity.END);
        progressRow.addView(timer, new LinearLayout.LayoutParams(-2, -2));
        progressDetails.addView(progressRow);
        stepProgress = new StepProgressView(this, accent, line);
        LinearLayout.LayoutParams stepParams = new LinearLayout.LayoutParams(-1, dp(4));
        stepParams.topMargin = dp(7);
        progressDetails.addView(stepProgress, stepParams);
        hero.addView(progressDetails);
        root.addView(hero);
    }

    private void buildDeviceCard() {
        LinearLayout deviceCard = card(GlassMaterial.Layer.CARD, 20, 14);
        deviceCard.addView(heading("设备信息"));
        deviceValue = text("—", 13, muted, false);
        buildValue = text("—", 13, muted, false);
        kernelValue = text("—", 13, muted, false);
        fitValue = text("待检测", 13, muted, false);
        addDeviceRow(deviceCard, "设备代号", deviceValue, true);
        addDeviceRow(deviceCard, "系统版本", buildValue, false);
        addDeviceRow(deviceCard, "内核版本", kernelValue, false);
        addDeviceRow(deviceCard, "适配状态", fitValue, false);
        root.addView(deviceCard);
    }

    private void buildLogCard() {
        LinearLayout logCard = card(GlassMaterial.Layer.CARD, 20, 10);
        LinearLayout bar = horizontalRow();
        bar.addView(heading("运行记录"), new LinearLayout.LayoutParams(0, -2, 1f));
        bar.addView(iconButton(R.drawable.ic_download, "导出日志", this::exportLog),
                new LinearLayout.LayoutParams(dp(44), dp(44)));
        logCard.addView(bar);
        emptyLog = text("暂无记录", 13, muted, false);
        emptyLog.setGravity(Gravity.CENTER);
        emptyLog.setMinHeight(dp(38));
        logCard.addView(emptyLog, new LinearLayout.LayoutParams(-1, -2));
        log = text("", 12, ink, false);
        log.setTypeface(Typeface.MONOSPACE);
        log.setTextIsSelectable(true);
        log.setLineSpacing(dp(3), 1f);
        log.setVisibility(View.GONE);
        logCard.addView(log, new LinearLayout.LayoutParams(-1, -2));
        root.addView(logCard);
    }

    private void buildMaintenanceCard() {
        LinearLayout maintenance = horizontalRow();
        maintenance.setPadding(0, 0, 0, dp(12));
        Button reboot = button("重启", false);
        Button softReboot = button("软重启", false);
        Button clean = button("清理临时文件", false);
        reboot.setOnClickListener(v -> confirm("重启", "确认立即重启？\n\n本次开机获取的临时 ROOT 将失效。", this::reboot));
        softReboot.setOnClickListener(v -> confirm("软重启", "将尝试重启系统服务，界面会短暂消失。确认继续？", this::softReboot));
        clean.setOnClickListener(v -> confirm("清理临时文件", "将清理日志与诊断程序，正在使用的 ROOT 组件会保留。确认继续？", this::cleanTemp));
        maintenance.addView(reboot, flatParams(0, 0));
        maintenance.addView(softReboot, flatParams(1, 6));
        maintenance.addView(clean, flatParams(2, 6));
        root.addView(collapsible("维护工具", maintenance));
    }

    private void showSettings() {
        Switch keepScreenOn = new Switch(this);
        keepScreenOn.setText("保持屏幕常亮");
        keepScreenOn.setTextColor(ink);
        keepScreenOn.setMinHeight(dp(48));
        keepScreenOn.setChecked(preferences.getBoolean("keep_screen_on", true));
        keepScreenOn.setOnCheckedChangeListener((button, checked) -> {
            applyKeepScreenOn(checked);
            preferences.edit().putBoolean("keep_screen_on", checked).apply();
        });
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(24), dp(8), dp(24), 0);
        content.addView(keepScreenOn, new LinearLayout.LayoutParams(-1, -2));
        content.addView(text("外观跟随系统", 13, muted, false));
        content.addView(text("版本 " + versionName(), 13, muted, false));
        new AlertDialog.Builder(this)
                .setTitle("设置")
                .setView(content)
                .setPositiveButton("完成", null)
                .show();
    }

    private void registerShizukuCallbacks() {
        Shizuku.addBinderReceivedListenerSticky(binderReceived);
        Shizuku.addBinderDeadListener(binderDead);
        Shizuku.addRequestPermissionResultListener(permissionResult);
    }

    private void refreshConnection() {
        runOnUiThread(() -> {
            if (isDestroyed()) return;
            WorkflowEngine.State state = engine.getState();
            updateShizukuStatus();
            if (state == WorkflowEngine.State.COMPLETE) {
                setHero(success);
                status.setText("全部完成 · KernelSU 已接管");
                action.setText("全部完成");
                action.setEnabled(false);
                spinner.setVisibility(View.GONE);
                stopTimer();
                return;
            }
            if (state == WorkflowEngine.State.ROOTED || state == WorkflowEngine.State.KSU_PENDING) {
                setHero(success);
                if (state == WorkflowEngine.State.ROOTED) {
                    status.setText("已获得临时 ROOT");
                }
                action.setText("重试 KernelSU 接管");
                action.setEnabled(true);
                spinner.setVisibility(View.GONE);
                return;
            }
            if (state == WorkflowEngine.State.RUNNING) {
                return;
            }
            if (!Shizuku.pingBinder()) {
                setHero(accent);
                status.setText("Shizuku 未运行");
                action.setText("一键临时 ROOT");
                action.setEnabled(true);
                return;
            }
            if (Shizuku.checkSelfPermission() != 0) {
                status.setText("需要授权");
                action.setText("一键临时 ROOT");
                action.setEnabled(true);
                return;
            }
            status.setText(state == WorkflowEngine.State.FAILED ? "上次运行失败 · 请重启后重试" : "可以开始");
            action.setText("一键临时 ROOT");
            action.setEnabled(true);
            engine.refreshDeviceInfo();
        });
    }

    private void onAction() {
        if (!Shizuku.pingBinder()) {
            openShizuku();
            return;
        }
        if (Shizuku.checkSelfPermission() != 0) {
            Shizuku.requestPermission(REQUEST_SHIZUKU);
            return;
        }
        WorkflowEngine.State state = engine.getState();
        if (state == WorkflowEngine.State.ROOTED || state == WorkflowEngine.State.KSU_PENDING) {
            startWorkflow(engine.retryKernelSu());
        } else if (state == WorkflowEngine.State.COMPLETE) {
            toast("KernelSU 已接管，无需重复操作。");
        } else {
            startWorkflow(engine.startRoot());
        }
    }

    private void onDiagnose() {
        if (!ensureShizuku()) {
            return;
        }
        startWorkflow(engine.diagnose());
    }

    private void startWorkflow(boolean started) {
        if (!started) {
            return;
        }
        startAt = SystemClock.elapsedRealtime();
        timing = true;
        mainHandler.removeCallbacks(timerTicker);
        mainHandler.post(timerTicker);
        action.setEnabled(false);
        diagnose.setEnabled(false);
        spinner.setVisibility(View.VISIBLE);
        progressDetails.setVisibility(View.VISIBLE);
        log.setText("");
        showLogContent();
        setHero(accent);
    }

    private boolean ensureShizuku() {
        if (!Shizuku.pingBinder()) {
            toast("请先启动 Shizuku。");
            openShizuku();
            return false;
        }
        if (Shizuku.checkSelfPermission() != 0) {
            Shizuku.requestPermission(REQUEST_SHIZUKU);
            return false;
        }
        return true;
    }

    private void openShizuku() {
        try {
            Intent launch = getPackageManager().getLaunchIntentForPackage("moe.shizuku.privileged.api");
            if (launch == null) {
                toast("未检测到 Shizuku，请先安装。");
            } else {
                startActivity(launch);
            }
        } catch (Throwable error) {
            toast("无法打开 Shizuku。");
        }
    }

    @Override
    public void onStatus(String value) {
        runOnUiThread(() -> status.setText(value));
    }

    @Override
    public void onLog(String value) {
        runOnUiThread(() -> {
            log.append(value);
            if (log.length() > 48000) {
                log.setText(log.getText().subSequence(Math.max(0, log.length() - 40000), log.length()));
            }
            showLogContent();
        });
    }

    @Override
    public void onTail(String value) {
        runOnUiThread(() -> {
            log.setText(lastLines(value, 14));
            showLogContent();
        });
    }

    @Override
    public void onStep(int step, String label) {
        runOnUiThread(() -> {
            stepLabel.setText(step >= 0 && step < WorkflowEngine.STEP_LABELS.length
                    ? "第 " + (step + 1) + "/" + WorkflowEngine.STEP_LABELS.length + " 步 · " + label
                    : label);
            stepProgress.setRatio(step < 0 ? 0f : Math.min(1f, (step + 0.5f) / WorkflowEngine.STEP_LABELS.length));
        });
    }

    @Override
    public void onDevice(DeviceSnapshot snapshot) {
        runOnUiThread(() -> {
            deviceValue.setText(snapshot.device);
            buildValue.setText(snapshot.build);
            kernelValue.setText(snapshot.kernel);
            fitValue.setText(snapshot.isKernelSupported() ? "已适配" : "未适配");
            fitValue.setTextColor(snapshot.isKernelSupported() ? success : danger);
        });
    }

    @Override
    public void onState(WorkflowEngine.State state, String message) {
        runOnUiThread(() -> {
            updateShizukuStatus();
            if (state == WorkflowEngine.State.RUNNING) progressDetails.setVisibility(View.VISIBLE);
            if (state == WorkflowEngine.State.RUNNING) {
                status.setText("正在运行");
                action.setEnabled(false);
                diagnose.setEnabled(false);
                spinner.setVisibility(View.VISIBLE);
                return;
            }
            stopTimer();
            spinner.setVisibility(View.GONE);
            diagnose.setEnabled(true);
            action.setEnabled(state != WorkflowEngine.State.COMPLETE);
            if (state == WorkflowEngine.State.ROOTED || state == WorkflowEngine.State.KSU_PENDING) {
                setHero(success);
                privilegeState.setText("已获得");
                status.setText(message);
                action.setText("重试 KernelSU 接管");
                vibrate();
            } else if (state == WorkflowEngine.State.COMPLETE) {
                setHero(success);
                privilegeState.setText("已获得");
                status.setText(message);
                action.setText("全部完成");
                stepProgress.setRatio(1f);
                vibrate();
            } else if (state == WorkflowEngine.State.FAILED) {
                setHero(danger);
                status.setText(message);
                action.setText("重启后重试");
            } else {
                setHero(muted);
                status.setText(message);
                action.setText("一键临时 ROOT");
            }
        });
    }

    private void exportLog() {
        String payload = buildLogPayload();
        String name = "lhasa26-" + new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date()) + ".log";
        new Thread(() -> {
            Uri uri = saveLog(name, payload);
            runOnUiThread(() -> {
                if (uri == null) {
                    toast("导出失败");
                    return;
                }
                new AlertDialog.Builder(this)
                        .setTitle("日志已导出")
                        .setMessage(name + "\n\n保存位置：Download/lhasa26")
                        .setNegativeButton("关闭", null)
                        .setPositiveButton("分享", (dialog, which) -> shareLog(uri, name))
                        .show();
            });
        }, "lhasa-export").start();
        toast("正在导出日志…");
    }

    private String buildLogPayload() {
        StringBuilder payload = new StringBuilder();
        payload.append("=== 环境 ===\n")
                .append("app=").append(versionName()).append('\n')
                .append("package=").append(getPackageName()).append('\n')
                .append("device=").append(Build.MODEL).append(" / ").append(Build.DEVICE).append('\n')
                .append("export=").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date())).append('\n')
                .append("state=").append(engine.getState()).append("\n\n")
                .append("=== 本次会话 ===\n")
                .append(engine.getSessionLog());
        return payload.toString();
    }

    private Uri saveLog(String name, String payload) {
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                ContentValues values = new ContentValues();
                values.put(MediaStore.Downloads.DISPLAY_NAME, name);
                values.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
                values.put(MediaStore.Downloads.RELATIVE_PATH, "Download/lhasa26");
                Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
                if (uri == null) {
                    return null;
                }
                try (OutputStream output = getContentResolver().openOutputStream(uri)) {
                    if (output == null) {
                        return null;
                    }
                    output.write(bytes);
                }
                return uri;
            } catch (Exception error) {
                onLog("写入下载目录失败：" + error + "\n");
            }
        }
        try {
            File directory = getExternalFilesDir(null);
            if (directory == null) {
                directory = getFilesDir();
            }
            File logs = new File(directory, "logs");
            if (!logs.exists() && !logs.mkdirs()) {
                return null;
            }
            File target = new File(logs, name);
            try (FileOutputStream output = new FileOutputStream(target)) {
                output.write(bytes);
            }
            return Uri.fromFile(target);
        } catch (Exception error) {
            return null;
        }
    }

    private void shareLog(Uri uri, String name) {
        Intent share = new Intent(Intent.ACTION_SEND);
        share.setType("text/plain");
        share.putExtra(Intent.EXTRA_SUBJECT, name);
        share.putExtra(Intent.EXTRA_STREAM, uri);
        share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try {
            startActivity(Intent.createChooser(share, "分享日志"));
        } catch (Exception error) {
            toast("未找到可用的分享应用。");
        }
    }

    private void reboot() {
        runMaintenance("reboot 2>/dev/null || svc power reboot 2>/dev/null", "重启指令已发送");
    }

    private void softReboot() {
        runMaintenance("kill -9 $(pidof system_server) 2>&1; echo rc=$?", "软重启指令已发送");
    }

    private void cleanTemp() {
        runMaintenance("cd /data/local/tmp 2>/dev/null; for f in uaf_replay.log uaf_replay.prev.log ksu_try.log diag.log .lhasa_failed_boot reach_probe slide_probe; do [ -e \"$f\" ] && rm -f \"$f\"; done; true", "临时文件已清理");
    }

    private void runMaintenance(String command, String success) {
        if (!ensureShizuku()) {
            return;
        }
        if (!engine.runMaintenance(command)) {
            toast("正在运行，维护操作已取消");
            return;
        }
        toast(success);
    }

    private void applyKeepScreenOn(boolean keep) {
        if (keep) {
            getWindow().addFlags(128);
        } else {
            getWindow().clearFlags(128);
        }
    }

    private void setHero(int color) {
        GradientDrawable ring = new GradientDrawable();
        ring.setShape(GradientDrawable.OVAL);
        ring.setColor(Color.TRANSPARENT);
        ring.setStroke(dp(2), color);
        statusRing.setBackground(ring);
    }

    private void showLogContent() {
        boolean hasLog = log.length() > 0;
        log.setVisibility(hasLog ? View.VISIBLE : View.GONE);
        emptyLog.setVisibility(hasLog ? View.GONE : View.VISIBLE);
    }

    private void updateShizukuStatus() {
        boolean connected = Shizuku.pingBinder();
        boolean authorized = connected && Shizuku.checkSelfPermission() == 0;
        String label = !connected ? "未连接" : authorized ? "已授权" : "待授权";
        shizukuState.setText(label);
        authorization.setEnabled(!authorized);
        if (Build.VERSION.SDK_INT >= 30) {
            authorization.setStateDescription(label);
        }
    }

    private LinearLayout card(GlassMaterial.Layer layer, int radius, int verticalPadding) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(glass.surface(layer, radius));
        card.setPadding(dp(16), dp(verticalPadding), dp(16), dp(verticalPadding));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(12);
        card.setLayoutParams(params);
        return card;
    }

    private LinearLayout collapsible(String label, View body) {
        LinearLayout card = card(GlassMaterial.Layer.CARD, 18, 0);
        Button header = new Button(this, null, android.R.attr.borderlessButtonStyle);
        header.setAllCaps(false);
        header.setText(label);
        header.setTextSize(15);
        header.setTypeface(Typeface.DEFAULT_BOLD);
        header.setTextColor(ink);
        header.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
        header.setPadding(0, 0, 0, 0);
        header.setMinHeight(dp(48));
        header.setCompoundDrawablesRelativeWithIntrinsicBounds(0, 0, R.drawable.ic_expand, 0);
        header.setCompoundDrawableTintList(ColorStateList.valueOf(muted));
        header.setContentDescription(label + "，已折叠");
        card.addView(header, new LinearLayout.LayoutParams(-1, -2));
        body.setVisibility(View.GONE);
        card.addView(body, new LinearLayout.LayoutParams(-1, -2));
        header.setOnClickListener(view -> {
            boolean expanded = body.getVisibility() != View.VISIBLE;
            body.setVisibility(expanded ? View.VISIBLE : View.GONE);
            header.setCompoundDrawablesRelativeWithIntrinsicBounds(0, 0,
                    expanded ? R.drawable.ic_collapse : R.drawable.ic_expand, 0);
            header.setContentDescription(label + (expanded ? "，已展开" : "，已折叠"));
        });
        return card;
    }

    private LinearLayout horizontalRow() {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        return row;
    }

    private TextView heading(String label) {
        TextView title = text(label, 16, ink, true);
        if (Build.VERSION.SDK_INT >= 28) title.setAccessibilityHeading(true);
        return title;
    }

    private TextView text(String value, float size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.DEFAULT_BOLD);
        return view;
    }

    private Button button(String label, boolean primary) {
        Button button = new Button(this);
        button.setAllCaps(false);
        button.setText(label);
        button.setTextSize(13);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setTextColor(primary ? getColor(R.color.on_accent) : ink);
        button.setMinHeight(0);
        button.setMinimumHeight(dp(44));
        button.setMinWidth(0);
        button.setMinimumWidth(0);
        button.setStateListAnimator(null);
        button.setBackgroundTintList(null);
        button.setBackground(ripple(primary));
        button.setPadding(dp(8), dp(7), dp(8), dp(7));
        return button;
    }

    private ImageButton iconButton(int icon, String description, Runnable run) {
        ImageButton button = new ImageButton(this);
        button.setContentDescription(description);
        button.setImageResource(icon);
        button.setImageTintList(ColorStateList.valueOf(ink));
        button.setBackgroundTintList(null);
        button.setBackground(ripple(false));
        button.setOnClickListener(view -> run.run());
        return button;
    }

    private RippleDrawable ripple(boolean primary) {
        GradientDrawable mask = new GradientDrawable();
        mask.setCornerRadius(dp(24));
        mask.setColor(Color.WHITE);
        if (primary) {
            GradientDrawable fill = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                    new int[]{getColor(R.color.accent_highlight), accent});
            fill.setCornerRadius(dp(24));
            fill.setStroke(dp(1), dark ? 0xA5D8FFF8 : 0x80AEF0E8);
            StateListDrawable backgrounds = new StateListDrawable();
            GradientDrawable disabled = new GradientDrawable();
            disabled.setCornerRadius(dp(24));
            disabled.setColor(getColor(R.color.accent_disabled));
            backgrounds.addState(new int[]{-android.R.attr.state_enabled}, disabled);
            backgrounds.addState(new int[0], fill);
            return new RippleDrawable(ColorStateList.valueOf(0x35FFFFFF), backgrounds, mask);
        }
        return new RippleDrawable(ColorStateList.valueOf(dark ? 0x35CBF8FF : 0x22467B88),
                glass.surface(GlassMaterial.Layer.BUTTON, 24), mask);
    }

    private LinearLayout.LayoutParams flatParams(int index, int gap) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, -2, 1f);
        if (index > 0) params.setMarginStart(dp(gap));
        return params;
    }

    private LinearLayout statusMetric(String label, TextView value) {
        LinearLayout pair = new LinearLayout(this);
        pair.setOrientation(LinearLayout.VERTICAL);
        pair.addView(text(label, 12, muted, false), new LinearLayout.LayoutParams(-1, -2));
        pair.addView(value, new LinearLayout.LayoutParams(-1, -2));
        return pair;
    }

    private void addDeviceRow(LinearLayout container, String label, TextView value, boolean first) {
        if (!first) {
            View divider = new View(this);
            divider.setBackgroundColor(line);
            container.addView(divider, new LinearLayout.LayoutParams(-1, 1));
        }
        LinearLayout row = horizontalRow();
        row.setPadding(0, dp(9), 0, dp(9));
        TextView name = text(label, 13, ink, false);
        LinearLayout.LayoutParams keyParams = new LinearLayout.LayoutParams(-2, -2);
        keyParams.setMarginEnd(dp(16));
        row.addView(name, keyParams);
        value.setGravity(Gravity.END);
        row.addView(value, new LinearLayout.LayoutParams(0, -2, 1f));
        container.addView(row, new LinearLayout.LayoutParams(-1, -2));
    }

    private void stopTimer() {
        timing = false;
        mainHandler.removeCallbacks(timerTicker);
        if (timer != null && startAt > 0) {
            timer.setText("用时 " + elapsedText(SystemClock.elapsedRealtime() - startAt));
        }
    }

    private void confirm(String title, String message, Runnable action) {
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(message)
                .setNegativeButton("取消", null)
                .setPositiveButton("确认", (dialog, which) -> action.run())
                .show();
    }

    private String versionName() {
        try {
            String version = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            return TextUtils.isEmpty(version) ? "dev" : version;
        } catch (Exception ignored) {
            return "dev";
        }
    }

    private String lastLines(String value, int count) {
        String[] lines = value.split("\\n");
        StringBuilder result = new StringBuilder();
        for (int i = Math.max(0, lines.length - count); i < lines.length; i++) {
            if (!lines[i].trim().isEmpty()) {
                result.append(lines[i]).append('\n');
            }
        }
        return result.toString();
    }

    private void vibrate() {
        try {
            Vibrator vibrator = (Vibrator) getSystemService(VIBRATOR_SERVICE);
            if (vibrator != null && vibrator.hasVibrator()) {
                vibrator.vibrate(VibrationEffect.createOneShot(60L, VibrationEffect.DEFAULT_AMPLITUDE));
            }
        } catch (Exception ignored) {
        }
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private static String elapsedText(long millis) {
        return String.format(Locale.US, "%.2f 秒", millis / 1000.0);
    }

    @Override
    protected void onDestroy() {
        Shizuku.removeRequestPermissionResultListener(permissionResult);
        Shizuku.removeBinderDeadListener(binderDead);
        Shizuku.removeBinderReceivedListener(binderReceived);
        timing = false;
        mainHandler.removeCallbacks(timerTicker);
        if (engine != null) {
            engine.stop();
        }
        super.onDestroy();
    }
}
