package com.gkeyes.lhasa26;

import android.app.AlertDialog;
import android.content.ContentValues;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;

import androidx.activity.ComponentActivity;

import com.gkeyes.lhasa26.core.DeviceSnapshot;
import com.gkeyes.lhasa26.core.LogRedactor;
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
 * Host for the Miuix console. ComponentActivity is required because AbstractComposeView resolves
 * ViewTreeLifecycleOwner and ViewTreeSavedStateRegistryOwner from the view tree.
 *
 * The primary action is never hard-disabled by Shizuku state: tapping it walks the user through
 * starting Shizuku and granting access, then runs the workflow.
 */
public final class ConsoleActivity extends ComponentActivity
        implements WorkflowCallbacks, FoldConsoleView.Listener {

    private static final int REQUEST_SHIZUKU = 1001;

    /**
     * 可安全清理的运行产物。
     *
     * 注意 `.lhasa_failed_boot` **不在**这里：它是「本次开机已经动过内核」的唯一记录，
     * 一旦在本次开机内被删掉，再点主按钮就可能对已释放节点二次 rb_erase 打 panic。
     * 它重启后自然失效，不需要也不允许手动清除。
     */
    private static final String CLEAN_TARGETS =
            "uaf_replay.log diag.log ksu_try.log .lhasa_stage";

    private WorkflowEngine engine;
    private ShizukuExecutor executor;
    private FoldConsoleView console;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final StringBuilder sessionLog = new StringBuilder();

    /**
     * 监听力必须持有引用才能注销。方法引用每次求值都是新对象，
     * removeXxxListener 拿它比对必然失败——这是之前注销不掉的根本原因。
     */
    private final Shizuku.OnBinderReceivedListener binderReceivedListener =
            () -> refreshAuthorization();
    private final Shizuku.OnBinderDeadListener binderDeadListener =
            () -> refreshAuthorization();
    private final Shizuku.OnRequestPermissionResultListener permissionResultListener =
            (code, result) -> refreshAuthorization();

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
    private boolean shizukuAlive;
    private boolean shizukuGranted;
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

        Shizuku.addBinderReceivedListenerSticky(binderReceivedListener);
        Shizuku.addBinderDeadListener(binderDeadListener);
        Shizuku.addRequestPermissionResultListener(permissionResultListener);

        keepScreenOn = getPreferences(MODE_PRIVATE).getBoolean("keep_on", true);
        applyKeepScreenOn();
        refreshAuthorization();
        engine.refreshDeviceInfo();
        render();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshAuthorization();
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        Shizuku.removeBinderReceivedListener(binderReceivedListener);
        Shizuku.removeBinderDeadListener(binderDeadListener);
        Shizuku.removeRequestPermissionResultListener(permissionResultListener);
        if (console != null) {
            console.attachListener(null);
        }
        if (engine != null) {
            engine.stop();
        }
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
            boolean wasGranted = shizukuGranted;
            shizukuAlive = Shizuku.pingBinder();
            shizukuGranted = false;
            if (shizukuAlive) {
                try {
                    shizukuGranted = Shizuku.checkSelfPermission() == 0;
                } catch (Throwable ignored) {
                    shizukuGranted = false;
                }
            }
            authorization = !shizukuAlive ? "未运行" : (shizukuGranted ? "已授权" : "需要授权");
            refreshActionLabel();
            render();
            if (shizukuGranted && !wasGranted && "—".equals(kernel) && engine != null) {
                engine.refreshDeviceInfo();
            }
        });
    }

    private void refreshActionLabel() {
        WorkflowEngine.State state = engine == null ? WorkflowEngine.State.IDLE : engine.getState();
        if (state == WorkflowEngine.State.ROOTED || state == WorkflowEngine.State.KSU_PENDING) {
            actionLabel = "加载 KernelSU";
            return;
        }
        if (state == WorkflowEngine.State.COMPLETE) {
            actionLabel = "全部完成";
            return;
        }
        if (!shizukuAlive) {
            actionLabel = "开启 Shizuku 并授权";
        } else if (!shizukuGranted) {
            actionLabel = "授权 Shizuku";
        } else {
            actionLabel = "一键临时 ROOT";
        }
    }

    private void render() {
        if (console == null) {
            return;
        }
        FoldUiState state = new FoldUiState(
                status, privilege, authorization, actionLabel, stepText, elapsed,
                device, build, kernel, compatibility,
                sessionLog.toString(), latest,
                !running, true, !running, running, running && !stepText.isEmpty(),
                keepScreenOn, 0f, versionName());
        console.render(state);
    }

    private boolean ensureShizukuOrPrompt() {
        refreshAuthorization();
        if (!Shizuku.pingBinder()) {
            status = "Shizuku 未运行，已为你打开 Shizuku";
            render();
            Intent launch = getPackageManager().getLaunchIntentForPackage("moe.shizuku.privileged.api");
            if (launch != null) {
                startActivity(launch);
            } else {
                toast("未安装 Shizuku");
            }
            return false;
        }
        int granted;
        try {
            granted = Shizuku.checkSelfPermission();
        } catch (Throwable error) {
            granted = -1;
        }
        if (granted != 0) {
            try {
                Shizuku.requestPermission(REQUEST_SHIZUKU);
                status = "请在 Shizuku 弹窗中允许本应用";
            } catch (Throwable error) {
                status = "无法请求 Shizuku 授权：" + error.getMessage();
            }
            render();
            return false;
        }
        return true;
    }

    @Override
    public void onEvent(FoldEvent event) {
        switch (event) {
            case PRIMARY: {
                if (!ensureShizukuOrPrompt()) {
                    break;
                }
                WorkflowEngine.State state = engine.getState();
                if (state == WorkflowEngine.State.COMPLETE) {
                    // KernelSU 已接管：绝不能再跑一遍 UAF（内核模块已加载，堆状态已变）。
                    toast("已接管 KernelSU，无需再执行；需要记录请先导出日志");
                    status = "已完成 · 如需重做请重启设备后再点";
                    render();
                    break;
                }
                if (state == WorkflowEngine.State.ROOTED || state == WorkflowEngine.State.KSU_PENDING) {
                    confirm("加载 KernelSU",
                            "会 late-load 加载内核模块，这是整条链里最容易导致重启的一步。\n"
                                    + "建议先把当前日志导出。确认现在加载？",
                            () -> {
                                if (engine.retryKernelSu()) {
                                    beginRun();
                                }
                            });
                } else if (engine.startRoot()) {
                    beginRun();
                }
                break;
            }
            case AUTHORIZE:
                ensureShizukuOrPrompt();
                break;
            case DIAGNOSE:
                if (ensureShizukuOrPrompt() && engine.diagnose()) {
                    beginRun();
                }
                break;
            case EXPORT:
                exportLog();
                break;
            case CLEAN:
                maintenance("cd /data/local/tmp 2>/dev/null; for f in " + CLEAN_TARGETS
                        + "; do [ -e \"$f\" ] && rm -f \"$f\"; done; true", "临时文件已清理");
                break;
            case SOFT_REBOOT:
                confirm("软重启", "将重启系统框架，未保存的内容可能丢失。", () ->
                        maintenance("kill -9 $(pidof system_server)", "软重启指令已提交"));
                break;
            case REBOOT:
                confirm("重启设备", "本次开机取得的临时 ROOT 会失效。", () ->
                        maintenance("reboot 2>/dev/null || svc power reboot 2>/dev/null", "重启指令已提交"));
                break;
            case HELP:
                new AlertDialog.Builder(this)
                        .setTitle("使用帮助")
                        .setMessage("1. 点击主按钮：自动打开 Shizuku 并请求授权\n"
                                + "2. 接口诊断确认环境\n"
                                + "3. 一键临时 ROOT（这一步跑完就停，不会自动加载 KernelSU）\n"
                                + "4. 需要常驻再点一次主按钮，会有二次确认\n"
                                + "5. 重启后临时 ROOT 失效，需要重新执行")
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
        refreshActionLabel();
        handler.removeCallbacks(ticker);
        handler.post(ticker);
        render();
    }

    private void maintenance(String command, String done) {
        if (!ensureShizukuOrPrompt()) {
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

    /**
     * 导出前统一脱敏；写入失败时把已经插进 MediaStore 的空条目删掉，
     * 否则 Download/lhasa26 下会积累 0 字节的残留文件。
     */
    private void exportLog() {
        String header = "app=" + versionName() + "\npackage=" + getPackageName()
                + "\ndevice=" + device + " / " + build + "\nkernel=" + kernel
                + "\nexport=" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date())
                + "\n\n";
        String payload = LogRedactor.redact(header + sessionLog);
        String name = "lhasa26-" + new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date()) + ".log";

        Uri uri = null;
        try {
            ContentValues values = new ContentValues();
            values.put(MediaStore.Downloads.DISPLAY_NAME, name);
            values.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
            values.put(MediaStore.Downloads.RELATIVE_PATH, "Download/lhasa26");
            uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
            if (uri == null) {
                toast("导出失败");
                return;
            }
            try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                if (out == null) {
                    throw new IllegalStateException("openOutputStream 返回空");
                }
                out.write(payload.getBytes(StandardCharsets.UTF_8));
            }
            toast("日志已导出到 Download/lhasa26/" + name);
        } catch (Exception error) {
            if (uri != null) {
                try {
                    getContentResolver().delete(uri, null, null);
                } catch (Exception ignored) {
                    // 清理失败不影响给用户的错误提示
                }
            }
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
                    handler.removeCallbacks(ticker);
                    break;
                case COMPLETE:
                    running = false;
                    privilege = "KernelSU 已接管";
                    handler.removeCallbacks(ticker);
                    break;
                case FAILED:
                    running = false;
                    privilege = "失败";
                    handler.removeCallbacks(ticker);
                    break;
                default:
                    running = false;
                    handler.removeCallbacks(ticker);
                    break;
            }
            refreshActionLabel();
            render();
        });
    }
}
