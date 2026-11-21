package com.gkeyes.lhasa26;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
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
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import com.gkeyes.lhasa26.core.CommandResult;
import com.gkeyes.lhasa26.core.DeviceSnapshot;
import com.gkeyes.lhasa26.core.KernelSupport;
import com.gkeyes.lhasa26.core.ShizukuExecutor;
import com.gkeyes.lhasa26.core.WorkflowCallbacks;
import com.gkeyes.lhasa26.core.WorkflowEngine;
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
    private static final int BG = 0xFFF2F1F7;
    private static final int INK = 0xFF1F2026;
    private static final int SUB = 0xFF8A8994;
    private static final int ACCENT = 0xFF3478F6;
    private static final int GREEN = 0xFF159447;
    private static final int RED = 0xFFD93632;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ShizukuExecutor executor = new ShizukuExecutor();
    private WorkflowEngine engine;
    private long startAt;
    private boolean timing;

    private LinearLayout root;
    private LinearLayout hero;
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
    private Button export;
    private ProgressBar spinner;
    private StepProgressView stepProgress;
    private ScrollView scroll;

    private final Runnable timerTicker = new Runnable() {
        @Override
        public void run() {
            if (!timing) {
                return;
            }
            timer.setText("用时 " + elapsedText(SystemClock.elapsedRealtime() - startAt));
            mainHandler.postDelayed(this, 50L);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        configureWindow(getWindow());
        engine = new WorkflowEngine(getAssets(), executor, this);
        buildUi();
        registerShizukuCallbacks();
        refreshConnection();
    }

    private void configureWindow(Window window) {
        window.setStatusBarColor(BG);
        window.setNavigationBarColor(BG);
        window.getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
    }

    private void buildUi() {
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), statusBarHeight() + dp(10), dp(16), navBarHeight() + dp(16));
        root.setBackgroundColor(BG);

        root.addView(text("v" + versionName(), 10, SUB, false));
        root.addView(text("LHASA · Android 设备工具链", 12, SUB, false));
        TextView title = text("临时 ROOT", 32, INK, true);
        title.setPadding(0, dp(4), 0, 0);
        root.addView(title);
        TextView subtitle = text("本次开机内有效 · 重启后失效", 13, SUB, false);
        subtitle.setPadding(0, dp(5), 0, 0);
        root.addView(subtitle);

        hero = new LinearLayout(this);
        hero.setOrientation(LinearLayout.VERTICAL);
        hero.setPadding(dp(16), dp(14), dp(16), dp(16));
        hero.setBackground(gradient(0xFF3478F6, 0xFF2850B8, 28));
        LinearLayout.LayoutParams heroParams = new LinearLayout.LayoutParams(-1, -2);
        heroParams.topMargin = dp(12);
        hero.setLayoutParams(heroParams);
        hero.addView(text("当前状态", 12, 0x99FFFFFF, false));

        LinearLayout statusRow = new LinearLayout(this);
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        status = text("正在检测", 24, Color.WHITE, true);
        statusRow.addView(status, new LinearLayout.LayoutParams(0, -2, 1f));
        spinner = new ProgressBar(this);
        spinner.setIndeterminate(true);
        spinner.setVisibility(View.GONE);
        statusRow.addView(spinner, new LinearLayout.LayoutParams(dp(22), dp(22)));
        hero.addView(statusRow);

        LinearLayout progressRow = new LinearLayout(this);
        progressRow.setGravity(Gravity.CENTER_VERTICAL);
        stepLabel = text("准备就绪", 12, 0xCCFFFFFF, false);
        progressRow.addView(stepLabel, new LinearLayout.LayoutParams(0, -2, 1f));
        timer = text("用时 0.00 秒", 12, 0xCCFFFFFF, false);
        timer.setGravity(Gravity.END);
        progressRow.addView(timer, new LinearLayout.LayoutParams(dp(110), -2));
        hero.addView(progressRow);

        stepProgress = new StepProgressView(this);
        LinearLayout.LayoutParams stepParams = new LinearLayout.LayoutParams(-1, dp(4));
        stepParams.topMargin = dp(7);
        hero.addView(stepProgress, stepParams);
        TextView shellHint = text("Shizuku 提供与 adb shell 相同的权限身份", 12, 0xB3FFFFFF, false);
        shellHint.setPadding(0, dp(8), 0, 0);
        hero.addView(shellHint);
        root.addView(hero);

        root.addView(section("设备"));
        LinearLayout deviceCard = listCard();
        deviceValue = text("—", 13, SUB, false);
        buildValue = text("—", 11, SUB, false);
        kernelValue = text("—", 11, SUB, false);
        fitValue = text("检测中", 13, SUB, false);
        deviceCard.addView(row("设备", deviceValue, false));
        deviceCard.addView(row("系统", buildValue, false));
        deviceCard.addView(row("内核", kernelValue, false));
        deviceCard.addView(row("适配", fitValue, false));
        deviceCard.addView(infoRow("支持", "18 Fold / 平板 9 Pro Max", true));
        root.addView(deviceCard);

        root.addView(section("操作"));
        action = primaryButton("一键临时 ROOT", ACCENT, Color.WHITE);
        action.setOnClickListener(v -> onAction());
        root.addView(action);

        LinearLayout secondary = new LinearLayout(this);
        secondary.setOrientation(LinearLayout.HORIZONTAL);
        diagnose = primaryButton("接口诊断", Color.WHITE, INK);
        diagnose.setLayoutParams(new LinearLayout.LayoutParams(0, -2, 1f));
        diagnose.setOnClickListener(v -> onDiagnose());
        export = primaryButton("导出日志", Color.WHITE, INK);
        LinearLayout.LayoutParams exportParams = new LinearLayout.LayoutParams(0, -2, 1f);
        exportParams.leftMargin = dp(10);
        export.setLayoutParams(exportParams);
        export.setOnClickListener(v -> exportLog());
        secondary.addView(diagnose);
        secondary.addView(export);
        root.addView(secondary);

        Button donate = primaryButton("捐赠", ACCENT, Color.WHITE);
        donate.setOnClickListener(v -> startActivity(new Intent(this, DonateActivity.class)));
        root.addView(donate);

        LinearLayout maintenance = new LinearLayout(this);
        maintenance.setOrientation(LinearLayout.HORIZONTAL);
        Button reboot = toneButton("重启");
        Button softReboot = toneButton("软重启");
        Button clean = toneButton("清理临时文件");
        reboot.setOnClickListener(v -> confirm("重启", "确认立即重启？\n\n本次开机获取的临时 ROOT 将失效。", this::reboot));
        softReboot.setOnClickListener(v -> confirm("软重启", "将尝试重启系统服务，界面会短暂消失。确认继续？", this::softReboot));
        clean.setOnClickListener(v -> confirm("清理临时文件", "将清理日志与诊断程序，正在使用的 ROOT 组件会保留。确认继续？", this::cleanTemp));
        maintenance.addView(reboot, flatParams(0, 0));
        maintenance.addView(softReboot, flatParams(1, 8));
        maintenance.addView(clean, flatParams(2, 8));
        root.addView(maintenance);

        root.addView(section("记录"));
        LinearLayout logCard = card();
        logCard.addView(text("运行记录", 14, INK, true));
        log = text("尚未开始。", 11, SUB, false);
        log.setTypeface(Typeface.MONOSPACE);
        log.setLineSpacing(dp(3), 1f);
        log.setPadding(0, dp(7), 0, 0);
        logCard.addView(log);
        root.addView(logCard);

        root.addView(section("帮助"));
        LinearLayout help = listCard();
        TextView helpTitle = text("使用帮助 · 点击展开", 13, INK, true);
        helpTitle.setPadding(0, dp(10), 0, dp(10));
        LinearLayout helpBody = new LinearLayout(this);
        helpBody.setOrientation(LinearLayout.VERTICAL);
        helpBody.setVisibility(View.GONE);
        help.addView(helpTitle);
        help.addView(helpBody);
        helpBody.addView(helpStep(1, "安装并启动 Shizuku", "首次使用需安装 Shizuku 并启动一次，通过无线调试启动。"));
        helpBody.addView(helpStep(2, "授权本应用", "首次点击按钮时允许 Shizuku 权限。"));
        helpBody.addView(helpStep(3, "一键临时 ROOT", "运行期间请勿锁屏、清理后台或重复点击。"));
        helpBody.addView(helpStep(4, "验证结果", "成功后可使用 /data/local/tmp/pc98260-su 执行 id 验证。"));
        helpBody.addView(helpStep(5, "KernelSU 接管", "临时 ROOT 成功后会自动尝试加载 KernelSU；失败时可再次点击重试。"));
        helpBody.addView(helpStep(6, "失败后须重启", "提权失败后请重启设备，再进行下一次尝试。"));
        helpTitle.setOnClickListener(v -> {
            boolean expand = helpBody.getVisibility() != View.VISIBLE;
            helpBody.setVisibility(expand ? View.VISIBLE : View.GONE);
            helpTitle.setText(expand ? "使用帮助 · 点击收起" : "使用帮助 · 点击展开");
        });
        root.addView(help);

        root.addView(section("设置"));
        LinearLayout settings = listCard();
        Switch keepScreenOn = new Switch(this);
        SharedPreferences preferences = getSharedPreferences("lhasa26", MODE_PRIVATE);
        boolean keep = preferences.getBoolean("keep_screen_on", true);
        keepScreenOn.setChecked(keep);
        applyKeepScreenOn(keep);
        keepScreenOn.setOnCheckedChangeListener((button, checked) -> {
            applyKeepScreenOn(checked);
            preferences.edit().putBoolean("keep_screen_on", checked).apply();
        });
        settings.addView(switchRow("保持屏幕常亮", "提权过程中避免 Shizuku 连接中断", keepScreenOn));
        root.addView(settings);

        root.addView(section("关于"));
        LinearLayout about = listCard();
        about.addView(infoRow("版本", versionName(), false));
        about.addView(infoRow("设备", "18 Fold（lhasa）\nPad 9 Pro Max（yingtian）", false));
        about.addView(infoRow("漏洞", "CVE-2026-98260", true));
        about.addView(infoRow("重构", "Lhasa26-Android · clean-room orchestration", true));
        root.addView(about);

        FrameLayout shell = new FrameLayout(this);
        shell.setBackgroundColor(BG);
        shell.addView(root, new FrameLayout.LayoutParams(-1, -2));
        scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        scroll.setBackgroundColor(BG);
        scroll.addView(shell, new ScrollView.LayoutParams(-1, -2));
        setContentView(scroll);
    }

    private void registerShizukuCallbacks() {
        Shizuku.addBinderReceivedListenerSticky(this::refreshConnection);
        Shizuku.addBinderDeadListener(this::refreshConnection);
        Shizuku.addRequestPermissionResultListener((requestCode, grantResult) -> refreshConnection());
    }

    private void refreshConnection() {
        runOnUiThread(() -> {
            WorkflowEngine.State state = engine.getState();
            if (state == WorkflowEngine.State.COMPLETE) {
                setHero(GREEN, 0xFF0C6236);
                status.setText("全部完成 · KernelSU 已接管");
                action.setText("全部完成");
                action.setEnabled(false);
                spinner.setVisibility(View.GONE);
                stopTimer();
                return;
            }
            if (state == WorkflowEngine.State.ROOTED || state == WorkflowEngine.State.KSU_PENDING) {
                setHero(GREEN, 0xFF0C6236);
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
                setHero(ACCENT, 0xFF2850B8);
                status.setText("Shizuku 未运行");
                action.setText("打开 Shizuku");
                action.setEnabled(true);
                return;
            }
            if (Shizuku.checkSelfPermission() != 0) {
                status.setText("需要授权");
                action.setText("请求 Shizuku 授权");
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
        log.setText("");
        setHero(ACCENT, 0xFF2850B8);
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
        });
    }

    @Override
    public void onTail(String value) {
        runOnUiThread(() -> log.setText(lastLines(value, 14)));
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
            fitValue.setTextColor(snapshot.isKernelSupported() ? GREEN : RED);
        });
    }

    @Override
    public void onState(WorkflowEngine.State state, String message) {
        runOnUiThread(() -> {
            if (state == WorkflowEngine.State.RUNNING) {
                status.setText("正在运行");
                return;
            }
            stopTimer();
            spinner.setVisibility(View.GONE);
            diagnose.setEnabled(true);
            action.setEnabled(state != WorkflowEngine.State.COMPLETE);
            if (state == WorkflowEngine.State.ROOTED || state == WorkflowEngine.State.KSU_PENDING) {
                setHero(GREEN, 0xFF0C6236);
                status.setText(message);
                action.setText("重试 KernelSU 接管");
                action.setTextColor(Color.WHITE);
                action.setBackground(buttonBackground(GREEN));
                vibrate();
            } else if (state == WorkflowEngine.State.COMPLETE) {
                setHero(GREEN, 0xFF0C6236);
                status.setText(message);
                action.setText("全部完成");
                action.setTextColor(Color.WHITE);
                action.setBackground(buttonBackground(GREEN));
                vibrate();
            } else if (state == WorkflowEngine.State.FAILED) {
                setHero(RED, 0xFF8E1E2B);
                status.setText(message);
                action.setText("重启后重试");
            } else {
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
        new Thread(() -> {
            try {
                CommandResult result = executor.run(command, true);
                runOnUiThread(() -> toast(result.isSuccess() ? success : "命令执行失败：" + result.output));
            } catch (Exception error) {
                runOnUiThread(() -> toast("命令执行失败：" + error.getMessage()));
            }
        }, "lhasa-maintenance").start();
    }

    private void applyKeepScreenOn(boolean keep) {
        if (keep) {
            getWindow().addFlags(128);
        } else {
            getWindow().clearFlags(128);
        }
    }

    private void setHero(int start, int end) {
        hero.setBackground(gradient(start, end, 28));
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

    private LinearLayout card() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(14), dp(16), dp(14));
        card.setBackground(round(Color.WHITE, 24));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(8);
        card.setLayoutParams(params);
        return card;
    }

    private LinearLayout listCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(4), dp(16), dp(4));
        card.setBackground(round(Color.WHITE, 26));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(6);
        card.setLayoutParams(params);
        return card;
    }

    private TextView section(String text) {
        TextView label = text(text, 12, SUB, true);
        label.setPadding(0, dp(16), 0, dp(3));
        return label;
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

    private Button primaryButton(String label, int background, int foreground) {
        Button button = new Button(this);
        button.setAllCaps(false);
        button.setText(label);
        button.setTextSize(13.2f);
        button.setTextColor(foreground);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setPadding(dp(14), dp(11), dp(14), dp(11));
        button.setMinHeight(0);
        button.setMinimumHeight(dp(44));
        button.setMinWidth(0);
        button.setMinimumWidth(0);
        button.setStateListAnimator(null);
        button.setBackground(buttonBackground(background));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(7);
        button.setLayoutParams(params);
        return button;
    }

    private Button toneButton(String label) {
        Button button = primaryButton(label, Color.WHITE, INK);
        button.setTextSize(11.5f);
        return button;
    }

    private LinearLayout.LayoutParams flatParams(int index, int gap) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, -2, 1f);
        if (index > 0) {
            params.leftMargin = dp(gap);
        }
        return params;
    }

    private LinearLayout row(String label, TextView value, boolean last) {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(10), 0, last ? dp(10) : 0);
        TextView key = text(label, 12, SUB, false);
        row.addView(key, new LinearLayout.LayoutParams(dp(58), -2));
        row.addView(value, new LinearLayout.LayoutParams(0, -2, 1f));
        if (!last) {
            row.setPadding(0, dp(10), 0, dp(5));
        }
        return row;
    }

    private LinearLayout infoRow(String label, String value, boolean last) {
        return row(label, text(value, 11, SUB, false), last);
    }

    private LinearLayout switchRow(String title, String description, Switch toggle) {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(9), 0, dp(9));
        LinearLayout labels = new LinearLayout(this);
        labels.setOrientation(LinearLayout.VERTICAL);
        labels.addView(text(title, 13, INK, true));
        TextView detail = text(description, 11, SUB, false);
        detail.setPadding(0, dp(3), 0, 0);
        labels.addView(detail);
        row.addView(labels, new LinearLayout.LayoutParams(0, -2, 1f));
        row.addView(toggle, new LinearLayout.LayoutParams(-2, -2));
        return row;
    }

    private LinearLayout helpStep(int number, String title, String detail) {
        LinearLayout row = new LinearLayout(this);
        row.setPadding(0, dp(7), 0, dp(7));
        TextView badge = text(String.valueOf(number), 12, Color.WHITE, true);
        badge.setGravity(Gravity.CENTER);
        badge.setBackground(round(ACCENT, 16));
        row.addView(badge, new LinearLayout.LayoutParams(dp(26), dp(26)));
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(10), 0, 0, 0);
        content.addView(text(title, 12.5f, INK, true));
        TextView body = text(detail, 11, SUB, false);
        body.setPadding(0, dp(3), 0, 0);
        content.addView(body);
        row.addView(content, new LinearLayout.LayoutParams(0, -2, 1f));
        return row;
    }

    private GradientDrawable round(int color, int radius) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(radius));
        return drawable;
    }

    private GradientDrawable gradient(int start, int end, int radius) {
        GradientDrawable drawable = new GradientDrawable(GradientDrawable.Orientation.TL_BR, new int[]{start, end});
        drawable.setCornerRadius(dp(radius));
        return drawable;
    }

    private GradientDrawable buttonBackground(int color) {
        return round(color, 18);
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

    private int statusBarHeight() {
        int id = getResources().getIdentifier("status_bar_height", "dimen", "android");
        return id > 0 ? getResources().getDimensionPixelSize(id) : dp(28);
    }

    private int navBarHeight() {
        int id = getResources().getIdentifier("navigation_bar_height", "dimen", "android");
        return id > 0 ? getResources().getDimensionPixelSize(id) : dp(24);
    }

    private static String elapsedText(long millis) {
        return String.format(Locale.US, "%.2f 秒", millis / 1000.0);
    }

    @Override
    protected void onDestroy() {
        timing = false;
        mainHandler.removeCallbacks(timerTicker);
        if (engine != null) {
            engine.stop();
        }
        super.onDestroy();
    }
}
