package com.gkeyes.lhasa26;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ContentValues;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;

import com.gkeyes.lhasa26.core.DeviceSnapshot;
import com.gkeyes.lhasa26.core.ShizukuExecutor;
import com.gkeyes.lhasa26.core.WorkflowCallbacks;
import com.gkeyes.lhasa26.core.WorkflowEngine;
import com.gkeyes.lhasa26.ui.FoldConsoleView;
import com.gkeyes.lhasa26.ui.FoldEvent;
import com.gkeyes.lhasa26.ui.FoldUiState;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import rikka.shizuku.Shizuku;

/**
 * Host for the Miuix console. It owns no UI logic of its own: the engine drives the state and the
 * console reports intents back as {@link FoldEvent}.
 */
public final class ConsoleActivity extends Activity
        implements WorkflowCallbacks, FoldConsoleView.Listener {

    private static final int REQUEST_SHIZUKU = 1001;

    private WorkflowEngine engine;
    private ShizukuExecutor executor;
    private FoldConsoleView console;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final StringBuilder sessionLog = new StringBuilder();

    private String status = "准备就绪";
    private String privilege = "未知";
    private String authorization = "检测中";
    private String actionLabel = "一键临时 ROOT";
    private String stepText = "";
    private String elapsed = "";
    private String device = "—";
    private String build = "—";
    private String kernel = "—";
    private String compatibility = "待检测";
    private String latest = "";
    private boolean running;
    private boolean authEnabled;
    private boolean mainEnabled;
    private boolean diagEnabled;
    private boolean keepScreenOn = true;
    private long startAt;

    private final Runnable ticker = new Runnable() {
        @Override
        public void run() {
            if (!running) {
                return;
            }
            elapsed = ((System.currentTimeMillis() - startAt) / 1000) + " s";
            render();
            handler.postDelayed(this, 1000L);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        executor = new ShizukuExecutor();
        engine = new WorkflowEngine(getAssets(), executor, this);

        console = new FoldConsoleView(this);
        console.setId(0x4c415353);
        console.setBrandName(getString(R.string.app_name));
        console.attachListener(this);
        setContentView(console);

        Shizuku.addBinderReceivedListenerSticky(this::refreshAuthorization);
        Shizuku.addBinderDeadListener(this::refreshAuthorization);
        Shizuku.addRequestPermissionResultListener((code, result) -> refreshAuthorization());

        keepScreenOn = getPreferences(MODE_PRIVATE).getBoolean("keep_on", true);
        applyKeepScreenOn();
        refreshAuthorization();
        engine.refreshDeviceInfo();
        render();
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        engine.stop();
        super.onDestroy();
    }

    private void applyKeepScreenOn() {
        if (keepScreenOn) {
            getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        } else {
            getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        }
    }

    private void refreshAuthorization() {
        runOnUiThread(() -> {
            boolean alive = Shizuku.pingBinder();
            boolean granted = false;
            if (alive) {
                try {
                    granted = Shizuku.checkSelfPermission() == 0;
                } catch (Throwable ignored) {
                    granted = false;
                }
            }
            authorization = !alive ? "Shizuku 未运行" : (granted ? "Shizuku 已授权" : "需要授权");
            authEnabled = true;
            if (!running) {
                mainEnabled = alive && granted;
                diagEnabled = alive && granted;
            }
            render();
        });
    }

    private void render() {
        if (console == null) {
            return;
        }
        FoldUiState state = new FoldUiState(
                status, privilege, authorization, actionLabel, stepText, elapsed,
                device, build, kernel, compatibility,
                sessionLog.toString(), latest,
                mainEnabled, authEnabled, diagEnabled, running, running && !stepText.isEmpty(),
                keepScreenOn, 0f, versionName());
        console.render(state);
    }

    @Override
    public void onEvent(FoldEvent event) {
        switch (event) {
            case PRIMARY:
                if (engine.getState() == WorkflowEngine.State.ROOTED
                        || engine.getState() == WorkflowEngine.State.KSU_PENDING) {
                    if (engine.retryKernelSu()) {
                        beginRun();
                    }
                } else if (engine.startRoot()) {
                    beginRun();
                }
                break;
            case AUTHORIZE:
                if (!Shizuku.pingBinder()) {
                    Intent launch = getPackageManager().getLaunchIntentForPackage("moe.shizuku.privileged.api");
                    if (launch != null) {
                        startActivity(launch);
                    } else {
                        toast("未安装 Shizuku");
                    }
                } else {
                    try {
                        Shizuku.requestPermission(REQUEST_SHIZUKU);
                    } catch (Throwable ignored) {
                        // Already granted or binder unavailable.
                    }
                }
                break;
            case DIAGNOSE:
                if (engine.diagnose()) {
                    beginRun();
                }
                break;
            case EXPORT:
                exportLog();
                break;
            case CLEAN:
                maintenance("cd /data/local/tmp 2>/dev/null; for f in uaf_replay.log diag.log ksu_try.log .lhasa_failed_boot; "
                        + "do [ -e \"$f\" ] && rm -f \"$f\"; done; true", "临时文件已清理");
                break;
            case SOFT_REBOOT:
                confirm("软重启", "将重启系统框架，未保存的内容可能丢失。", () ->
                        maintenance("kill -9 $(pidof system_server)", "软重启指令已发送"));
                break;
            case REBOOT:
                confirm("重启设备", "本次开机取得的临时 ROOT 会失效。", () ->
                        maintenance("reboot 2>/dev/null || svc power reboot 2>/dev/null", "重启指令已发送"));
                break;
            case HELP:
                new AlertDialog.Builder(this)
                        .setTitle("使用帮助")
                        .setMessage("1. 启动 Shizuku 并授权\n2. 接口诊断确认环境\n3. 一键临时 ROOT\n4. 成功后 KernelSU 接管，重启后需重新执行")
                        .setPositiveButton("知道了", null)
                        .show();
                break;
            case KEEP_ON:
                keepScreenOn = !keepScreenOn;
                getPreferences(MODE_PRIVATE).edit().putBoolean("keep_on", keepScreenOn).apply();
                applyKeepScreenOn();
                render();
                break;
            default:
                break;
        }
    }

    private void beginRun() {
        running = true;
        startAt = System.currentTimeMillis();
        handler.removeCallbacks(ticker);
        handler.post(ticker);
        render();
    }

    private void maintenance(String command, String done) {
        if (!"Shizuku 已授权".equals(authorization)) {
            toast("请先授权 Shizuku");
            return;
        }
        if (!engine.runMaintenance(command)) {
            toast("正在运行，操作已取消");
            return;
        }
        toast(done);
    }

    private void confirm(String title, String message, Runnable action) {
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(message)
                .setNegativeButton("取消", null)
                .setPositiveButton("继续", (dialog, which) -> action.run())
                .show();
    }

    private void exportLog() {
        String payload = "app=" + versionName() + "\npackage=" + getPackageName()
                + "\ndevice=" + device + " / " + build + "\nkernel=" + kernel
                + "\nexport=" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date())
                + "\n\n" + sessionLog;
        String name = "lhasa26-" + new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date()) + ".log";
        try {
            ContentValues values = new ContentValues();
            values.put(MediaStore.Downloads.DISPLAY_NAME, name);
            values.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
            values.put(MediaStore.Downloads.RELATIVE_PATH, "Download/lhasa26");
            Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
            if (uri == null) {
                toast("导出失败");
                return;
            }
            try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                if (out != null) {
                    out.write(payload.getBytes(StandardCharsets.UTF_8));
                }
            }
            toast("日志已导出到 Download/lhasa26/" + name);
        } catch (Exception error) {
            toast("导出失败：" + error.getMessage());
        }
    }

    private String versionName() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception ignored) {
            return "";
        }
    }

    private void toast(String text) {
        runOnUiThread(() -> android.widget.Toast.makeText(this, text, android.widget.Toast.LENGTH_SHORT).show());
    }

    // ---- WorkflowCallbacks ----

    @Override
    public void onStatus(String text) {
        runOnUiThread(() -> {
            status = text;
            render();
        });
    }

    @Override
    public void onLog(String line) {
        runOnUiThread(() -> {
            sessionLog.append(line);
            if (sessionLog.length() > 60000) {
                sessionLog.delete(0, sessionLog.length() - 40000);
            }
            render();
        });
    }

    @Override
    public void onTail(String text) {
        runOnUiThread(() -> {
            latest = text == null ? "" : text;
            render();
        });
    }

    @Override
    public void onStep(int index, String label) {
        runOnUiThread(() -> {
            stepText = label == null ? "" : label;
            render();
        });
    }

    @Override
    public void onDevice(DeviceSnapshot snapshot) {
        runOnUiThread(() -> {
            if (snapshot == null) {
                return;
            }
            device = snapshot.device;
            build = snapshot.build;
            kernel = snapshot.kernel;
            compatibility = snapshot.isKernelSupported() ? "已适配" : "未适配";
            render();
        });
    }

    @Override
    public void onState(WorkflowEngine.State state, String message) {
        runOnUiThread(() -> {
            if (message != null) {
                status = message;
            }
            switch (state) {
                case RUNNING:
                    running = true;
                    mainEnabled = false;
                    diagEnabled = false;
                    if (startAt == 0) {
                        startAt = System.currentTimeMillis();
                    }
                    handler.removeCallbacks(ticker);
                    handler.post(ticker);
                    break;
                case ROOTED:
                case KSU_PENDING:
                    running = false;
                    privilege = "临时 ROOT";
                    actionLabel = "重试 KernelSU 接管";
                    mainEnabled = true;
                    diagEnabled = true;
                    handler.removeCallbacks(ticker);
                    break;
                case COMPLETE:
                    running = false;
                    privilege = "临时 ROOT";
                    actionLabel = "全部完成";
                    mainEnabled = false;
                    diagEnabled = true;
                    handler.removeCallbacks(ticker);
                    break;
                case FAILED:
                    running = false;
                    privilege = "失败";
                    actionLabel = "重试";
                    mainEnabled = true;
                    diagEnabled = true;
                    handler.removeCallbacks(ticker);
                    break;
                default:
                    running = false;
                    actionLabel = "一键临时 ROOT";
                    mainEnabled = true;
                    diagEnabled = true;
                    handler.removeCallbacks(ticker);
                    break;
            }
            render();
        });
    }
}
