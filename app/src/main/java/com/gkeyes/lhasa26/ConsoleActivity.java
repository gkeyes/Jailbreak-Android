package com.gkeyes.lhasa26;

import android.content.ContentValues;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.res.Configuration;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.view.WindowInsetsController;

import androidx.activity.ComponentActivity;

import com.gkeyes.lhasa26.core.DeviceSnapshot;
import com.gkeyes.lhasa26.core.LogRedactor;
import com.gkeyes.lhasa26.core.RootPath;
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
 * Host for the Miuix console.
 *
 * 确认框与帮助文案统一由 Compose 层（FoldDialogs）负责，宿主只执行动作：
 * 那里已经弹过一次窗，这里再弹就会出现两个风格不同的确认框。
 */
public final class ConsoleActivity extends ComponentActivity
        implements WorkflowCallbacks, FoldConsoleView.Listener {

    private static final int REQUEST_SHIZUKU = 1001;

    /** 提权路径的持久化键，仿 keep_on：SharedPreferences(MODE_PRIVATE)。 */
    private static final String PREF_ROOT_PATH = "root_path";

    /**
     * 完整框架重启：zygote 会全新拉起，Zygisk 因此在 zygote 启动时重新注入，
     * LSPosed 随之生效。只 `ctl.restart zygote` 不会重建这套注入链。
     */
    private static final String SOFT_REBOOT_COMMAND = "/system/bin/su -c 'stop; start'";

    /**
     * 可安全清理的运行产物。
     *
     * `.lhasa_failed_boot` **不在**这里：它是「本次开机已经动过内核」的唯一记录，
     * 一旦在本次开机内被删掉，再点主按钮就可能对已释放节点二次 rb_erase 打 panic。
     */
    private static final String CLEAN_TARGETS =
            "uaf_replay.log diag.log ksu_try.log .lhasa_stage .lhasa_slide";

    private WorkflowEngine engine;
    private ShizukuExecutor executor;
    private FoldConsoleView console;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final StringBuilder sessionLog = new StringBuilder();

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

    /** 当前选中的提权路径（持久化到 root_path，默认 98260）。 */
    private RootPath selectedRootPath = RootPath.TIMER_98260;
    /** 99491 profile 是否可用（fail-closed：未校验/校验中一律按不可用处理）。 */
    private boolean cve99491Available;
    private String cve99491Reason = "";
    private boolean availabilityRequested;

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
        // 真机标定阶段：debug 包允许 verified=0 的 99491 profile 带警告运行；release 包一律 fail-closed。
        engine.setUnverifiedProfileAllowed(isDebuggableBuild());
        // 路径选择持久化仿 keep_on：存 string，读不到/非法值回落 98260。
        selectedRootPath = RootPath.fromKey(
                getPreferences(MODE_PRIVATE).getString(PREF_ROOT_PATH, null));
        engine.setRootPath(selectedRootPath);

        console = new FoldConsoleView(this);
        console.setId(0x4c415353);
        console.setBrandName(getString(R.string.app_name));
        console.attachListener(this);
        setContentView(console);
        updateSystemBarAppearance(getResources().getConfiguration());

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
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        updateSystemBarAppearance(configuration);
    }

    private void updateSystemBarAppearance(Configuration configuration) {
        WindowInsetsController controller = getWindow().getInsetsController();
        if (controller != null) {
            int mask = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                    | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
            boolean dark = (configuration.uiMode & Configuration.UI_MODE_NIGHT_MASK)
                    == Configuration.UI_MODE_NIGHT_YES;
            controller.setSystemBarsAppearance(dark ? 0 : mask, mask);
        }
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

    /** debug 包：允许 verified=0 的 99491 profile 带警告运行（真机标定阶段）。 */
    private boolean isDebuggableBuild() {
        try {
            return (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** 当前路径是否可运行：98260 恒可用；99491 取决于 profile 可用性（fail-closed）。 */
    private boolean isSelectedPathAvailable() {
        return selectedRootPath != RootPath.WACOM_99491 || cve99491Available;
    }

    private void persistRootPath() {
        getPreferences(MODE_PRIVATE).edit()
                .putString(PREF_ROOT_PATH, selectedRootPath.key())
                .apply();
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
            if (shizukuGranted) {
                if (!availabilityRequested && engine != null) {
                    availabilityRequested = true;
                    engine.refreshRootPathAvailability();
                }
            } else {
                availabilityRequested = false;
                cve99491Available = false;
                cve99491Reason = shizukuAlive
                        ? "等待 Shizuku 授权后校验 99491 profile"
                        : "需要先启动 Shizuku 并授权，才能校验 99491 profile";
            }
            refreshActionLabel();
            render();
            if (shizukuGranted && !wasGranted && "—".equals(kernel) && engine != null) {
                engine.refreshDeviceInfo();
            }
        });
    }

    private void refreshActionLabel() {
        WorkflowEngine.State state = engine == null ? WorkflowEngine.State.IDLE : engine.getState();
        if (state == WorkflowEngine.State.ROOTED) {
            actionLabel = "接管 KernelSU";
            return;
        }
        if (state == WorkflowEngine.State.KSU_PENDING) {
            actionLabel = "重试 KernelSU 接管";
            return;
        }
        if (state == WorkflowEngine.State.COMPLETE) {
            actionLabel = "全部完成";
            return;
        }
        if (state == WorkflowEngine.State.PARKED) {
            actionLabel = "已 PARKED · 请重启设备";
            return;
        }
        if (!isSelectedPathAvailable()) {
            actionLabel = "99491 未适配 · 请切换路径";
            return;
        }
        if (!shizukuAlive) {
            actionLabel = "开启 Shizuku 并授权";
        } else if (!shizukuGranted) {
            actionLabel = "授权 Shizuku";
        } else {
            actionLabel = selectedRootPath == RootPath.WACOM_99491
                    ? "一键临时 ROOT · 99491"
                    : "一键临时 ROOT";
        }
    }

    private void render() {
        if (console == null) {
            return;
        }
        boolean pathAvailable = isSelectedPathAvailable();
        FoldUiState state = new FoldUiState(
                status, privilege, authorization, actionLabel, stepText, elapsed,
                device, build, kernel, compatibility,
                sessionLog.toString(), latest,
                !running && pathAvailable, true, !running && pathAvailable, running,
                running && !stepText.isEmpty(),
                keepScreenOn, 0f, versionName(),
                selectedRootPath.key(), cve99491Available, cve99491Reason);
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
                if (!isSelectedPathAvailable()) {
                    toast(cve99491Reason.isEmpty()
                            ? "99491 未适配：profile 未通过校验"
                            : "99491 不可用：" + cve99491Reason);
                    refreshActionLabel();
                    render();
                    break;
                }
                WorkflowEngine.State state = engine.getState();
                if (state == WorkflowEngine.State.COMPLETE) {
                    toast("已接管 KernelSU，无需再执行；需要记录请先导出日志");
                    status = "已完成 · 如需重做请重启设备后再点";
                    render();
                    break;
                }
                if (state == WorkflowEngine.State.ROOTED || state == WorkflowEngine.State.KSU_PENDING) {
                    // 正常流程里引擎已经自动接管；这里只处理接管失败后的手动重试。
                    if (engine.retryKernelSu()) {
                        beginRun();
                    }
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
                // Compose 层已确认过；这里直接执行，避免第二次弹窗。
                maintenance(SOFT_REBOOT_COMMAND, "已提交框架重启");
                break;
            case REBOOT:
                maintenance("reboot 2>/dev/null || svc power reboot 2>/dev/null", "重启指令已提交");
                break;
            case KEEP_ON:
                keepScreenOn = !keepScreenOn;
                getPreferences(MODE_PRIVATE).edit().putBoolean("keep_on", keepScreenOn).apply();
                applyKeepScreenOn();
                render();
                break;
            case PATH_SELECT: {
                if (running) {
                    toast("正在运行，暂不能切换提权路径");
                    break;
                }
                RootPath next = selectedRootPath == RootPath.TIMER_98260
                        ? RootPath.WACOM_99491
                        : RootPath.TIMER_98260;
                if (next == RootPath.WACOM_99491 && !cve99491Available) {
                    toast(cve99491Reason.isEmpty()
                            ? "99491 未适配：profile 未通过校验"
                            : "99491 不可用：" + cve99491Reason);
                    break;
                }
                selectedRootPath = next;
                engine.setRootPath(next);
                persistRootPath();
                status = next == RootPath.WACOM_99491
                        ? "已切换到 99491（CVE-2026-99491 · 实验路径 · opt-in）"
                        : "已切换到 98260（默认路径 · 稳定）";
                refreshActionLabel();
                render();
                break;
            }
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

    private void exportLog() {
        String activePath = engine == null ? selectedRootPath.key() : engine.getActivePath().key();
        String profileSha = engine == null ? "" : engine.getProfileSha256();
        String stageLabel = engine == null ? "" : engine.getLastStepLabel();
        String chainElapsed = engine == null || engine.getChainElapsedMs() <= 0L
                ? elapsed
                : String.format(Locale.US, "%.1fs", engine.getChainElapsedMs() / 1000.0);
        String header = "app=" + versionName() + "\npackage=" + getPackageName()
                + "\ndevice=" + device + " / " + build + "\nkernel=" + kernel
                + "\nroot_path=" + selectedRootPath.key()
                + "\nactive_path=" + activePath
                + "\nprofile_sha256=" + (profileSha.isEmpty() ? "—" : profileSha)
                + "\nstage=" + (stageLabel.isEmpty() ? "—" : stageLabel)
                + "\nelapsed=" + (chainElapsed.isEmpty() ? "—" : chainElapsed)
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
            // 99491 profile 的 release 匹配依赖设备内核版本，拿到内核后重新校验一次（fail-closed）。
            if (shizukuGranted && engine != null) {
                engine.refreshRootPathAvailability();
            }
            render();
        });
    }

    @Override
    public void onRootPathAvailability(boolean available, String reason) {
        runOnUiThread(() -> {
            cve99491Available = available;
            cve99491Reason = reason == null ? "" : reason;
            refreshActionLabel();
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
                case PARKED:
                    running = false;
                    privilege = "已 PARKED（本 boot 不再写内核）";
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
