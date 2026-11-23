package com.gkeyes.lhasa26.core;

import android.content.res.AssetManager;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Owns the long-running workflow. UI code only receives immutable events and never runs shell work.
 * The supplied native payloads are built from upstream (MIT) or in-repo sources; orchestration and
 * state handling are our code.
 */
public final class WorkflowEngine implements AssetDeployer.WorkflowLog {
    public enum State { IDLE, RUNNING, ROOTED, KSU_PENDING, COMPLETE, FAILED }

    public static final String[] STEP_LABELS = {
            "校验内核", "部署程序", "测量内核地址", "等待系统空闲",
            "提权执行", "结果验证", "KernelSU 接管"
    };

    private static final long IDLE_AVAILABLE_KB = 1500000L;
    private static final long CLEAN_SKIP_AVAILABLE_KB = 3000000L;
    private static final long DEPLOY_TIMEOUT_MS = 8000L;
    private static final int TEMP_ROOT_PROBE_TIMEOUT_S = 3;
    private static final String RUN_MARKER = "/data/local/tmp/.lhasa_run";
    private static final String ROOTD_SOCKET = "/data/local/tmp/pc98260-root.sock";
    private static final String SU_CLIENT = "/data/local/tmp/pc98260-su";
    private static final String KSUD_FILE = "/data/local/tmp/ksud";
    private static final String EXPLOIT_BINARIES = "uaf_plant_replay slide_probe reach_probe";
    private static final int SLIDE_PROBE_TIMEOUT_S = 12;
    private static final int DIAGNOSE_TIMEOUT_S = 25;
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
    private final Set<String> payloadLines = new LinkedHashSet<>();
    /** payload 启动时刻（毫秒），用于给每行输出打相对时间戳。 */
    private volatile long payloadStartAt;
    private volatile State state = State.IDLE;
    private volatile long startedAt;
    private volatile int currentStep = -1;
    private volatile boolean busy;
    private volatile boolean rootBeforeRun;
    private volatile String enforceBeforeRun = "";
    private volatile String selinuxAfterRoot = "?";
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
        return getShareableLog();
    }

    public String getRawSessionLog() {
        synchronized (logLock) {
            return sessionLog.toString();
        }
    }

    public String getShareableLog() {
        return getRawSessionLog().replaceAll("0x[0-9a-fA-F]{6,}", "0x<addr>");
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

    /** 从 payload 启动算起的秒数，用于给输出行打戳。 */
    private double payloadElapsed() {
        long start = payloadStartAt;
        if (start <= 0L) {
            return 0.0;
        }
        return (System.currentTimeMillis() - start) / 1000.0;
    }

    /**
     * 把 payload 的新增输出写进会话日志（去重），每条带相对时间前缀。
     *
     * 前缀是这条日志第一次被看到的时刻（轮询 500ms，所以分辨率约 0.5s），
     * 足以区分「fork+写入慢」和「卡在等待」这两种不同的慢法。
     */
    private void appendPayloadOutput(String tail) {
        if (tail == null || tail.trim().isEmpty()) {
            return;
        }
        for (String line : tail.split("\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (payloadLines.add(trimmed)) {
                append(String.format(Locale.US, "[t+%5.1fs] %s", payloadElapsed(), trimmed));
            }
        }
    }

    @FunctionalInterface
    private interface WorkflowTask {
        void run() throws Exception;
    }

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
                payloadLines.clear();
                payloadStartAt = 0L;
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
                    callbacks.onState(state, "操作已中断");
                }
            } catch (Throwable failure) {
                append(friendly(failure));
                if (ownsState) {
                    fail(friendly(failure));
                } else {
                    String message = "诊断失败 · " + friendly(failure);
                    callbacks.onStatus(message);
                    callbacks.onState(state, message);
                }
            } finally {
                busy = false;
                if (ownsState) {
                    cleanupBinaries(state == State.ROOTED || state == State.KSU_PENDING);
                }
            }
        });
        return true;
    }

    private void runRootChain() throws Exception {
        long chainStart = System.currentTimeMillis();
        step(0);
        status("核对内核");
        Map<String, String> preflight = fetchPreflightSnapshot();
        String kernel = preflight.getOrDefault("UNAME", "");
        append("uname -r = " + kernel);
        if (!BootGuard.isSupportedKernel(kernel)) {
            append(BootGuard.kernelWarning(kernel));
        }
        String boot = preflight.getOrDefault("BOOT", "");
        applyBaseline(preflight);

        if (rootBeforeRun) {
            clearRunMarker();
            run(BootGuard.clearStageCommand(), true);
            state = State.COMPLETE;
            selinuxAfterRoot = enforceNow();
            append("[跳过] 检测到 /system/bin/su 已可用且为 uid=0 —— 本机已由 KernelSU 接管。");
            append("[跳过] 不再执行 UAF 提权；如需重新验证请先重启设备。");
            callbacks.onState(State.COMPLETE,
                    "已由 KernelSU 接管 · 无需执行 · SELinux " + selinuxAfterRoot);
            return;
        }

        if (hasUsableTempRoot()) {
            append("[复用] 临时 ROOT 仍可用，跳过部署/测量/提权，直接接管 KernelSU。");
            run(BootGuard.clearFailureCommand(), true);
            clearRunMarker();
            state = State.ROOTED;
            selinuxAfterRoot = enforceNow();
            callbacks.onState(State.ROOTED, "复用已有临时 ROOT · 正在接管 KernelSU");
            runKernelSuStep();
            return;
        }

        if (payloadProcessCount() > 0) {
            throw new IllegalStateException("上次运行的进程仍在运行，请重启设备后重试。");
        }
        writeRunMarker(boot);
        String hint = BootGuard.leftoverStageHint(preflight.getOrDefault("STAGE", ""));
        if (!hint.isEmpty()) {
            append("[上次] " + hint);
        }

        String recorded = preflight.getOrDefault("FAILED", "").trim();
        BootGuard.Retry retry = BootGuard.parseFailure(recorded, boot);
        if (retry == BootGuard.Retry.BLOCKED) {
            throw new IllegalStateException(
                    "本次开机已发生节点挂树（holding zombie）或内核报错，禁止重跑——重跑会对已释放节点二次 rb_erase，"
                            + "直接 panic。请重启设备后再试。");
        }
        if (retry == BootGuard.Retry.PERMISSIVE_RETRY) {
            append("（提示）本次开机已为 Permissive，将直接重试 cred 阶段。");
        }

        step(1);
        status("部署程序");
        final DeployGate deployGate = new DeployGate(DEPLOY_TIMEOUT_MS);
        Thread deploy = new Thread(() -> {
            try {
                deployer.stageAll();
                deployGate.markCompleted();
            } catch (Throwable error) {
                deployGate.fail(error);
            }
        }, "lhasa-deploy");
        deploy.start();
        DeployGate.Result deployResult = deployGate.await(deploy);
        if (deployResult != DeployGate.Result.READY) {
            recordFailedBoot(boot, false);
            throw new IllegalStateException("部署未完成（" + deployResult + "）· 请重启后重试");
        }

        step(2);
        status("测量本次开机的内核地址");
        String addressArgument = measureAddress(boot);

        step(3);
        status("等待系统空闲");
        cleanMemory();
        waitForIdle();

        step(4);
        status("提权执行中，请稍候");
        run(BootGuard.markCommand("payload"), true);
        String failureReason = runPayload(addressArgument, boot);
        if (failureReason != null) {
            stopPayload();
            if (!failureReason.isEmpty()) {
                throw new IllegalStateException(failureReason);
            }
            recordFailedBoot(boot, false);
            throw new IllegalStateException("提权失败 · 请重启设备");
        }

        step(5);
        status("验证");
        CommandResult verify = run(SU_CLIENT + " -c 'id; getenforce; grep CapEff /proc/self/status'", false);
        append(verify.output);
        if (!isRoot(verify.output)) {
            recordFailedBoot(boot, false);
            throw new IllegalStateException("rootd 无响应 · 请重启设备");
        }
        run(BootGuard.clearFailureCommand(), true);
        clearRunMarker();
        run(BootGuard.clearStageCommand(), true);
        state = State.ROOTED;
        selinuxAfterRoot = enforceNow();
        callbacks.onStatus("已获得临时 ROOT · SELinux " + selinuxAfterRoot);
        append("临时 ROOT 已就绪。");
        append("[归因] 开始时为 shell（未持有 root），结束时获得 uid=0 · SELinux "
                + (enforceBeforeRun.isEmpty() ? "?" : enforceBeforeRun) + " → " + selinuxAfterRoot);
        append(String.format(Locale.US, "[耗时] 从点击到临时 ROOT 就绪 %.1fs",
                (System.currentTimeMillis() - chainStart) / 1000.0));
        append("[下一步] 自动接管 KernelSU（会加载内核模块，可能重启）。");
        runKernelSuStep();
    }

    private boolean hasUsableTempRoot() {
        try {
            if (!socketExists()) {
                return false;
            }
            if (!"yes".equals(run("test -x " + SU_CLIENT + " && echo yes || echo no", true).output.trim())) {
                return false;
            }
            CommandResult probe = run(BootGuard.withTimeout(TEMP_ROOT_PROBE_TIMEOUT_S,
                    SU_CLIENT + " -c 'id'"), true);
            return isRoot(probe.output);
        } catch (Exception ignored) {
            return false;
        }
    }

    private void runDiagnosis() throws Exception {
        status("正在诊断");
        deployer.stage("reach_probe");
        deployer.stage("slide_probe");
        run(BootGuard.markCommand("diagnose"), true);
        CommandResult result = run(BootGuard.withTimeout(DIAGNOSE_TIMEOUT_S,
                "/data/local/tmp/reach_probe > /data/local/tmp/diag.log 2>&1"), true);
        String report = run("cat /data/local/tmp/diag.log 2>/dev/null", true).output;
        if (report.trim().isEmpty()) {
            report = result.output;
        }
        append(report);
        if (result.exitCode == BootGuard.TIMEOUT_EXIT) {
            append("[诊断] reach_probe 超过 " + DIAGNOSE_TIMEOUT_S + " 秒被 timeout 终止——探针卡住了，不是环境不合格。");
        }
        run("echo '!enable_event:kmem:kmem_cache_alloc' > /sys/kernel/tracing/events/kmem/rss_stat/trigger 2>/dev/null; echo 0 > /sys/kernel/tracing/tracing_on 2>/dev/null", true);
        run(BootGuard.clearStageCommand(), true);
        String patch = run("getprop ro.build.version.security_patch", true).output.trim();
        append("[诊断] security_patch=" + (patch.isEmpty() ? "未知" : patch)
                + (patch.isEmpty() ? "" : (patch.compareTo("2026-10-06") < 0
                ? " · 未修补窗口"
                : " · 可能已回补")));
        CommandResult probe = run(BootGuard.withTimeout(SLIDE_PROBE_TIMEOUT_S,
                "/data/local/tmp/slide_probe"), true);
        append(filterProbe(probe.output));
        String slide = KernelSupport.extractSlide(probe.output);
        boolean usable = slide != null && KernelSupport.isSlideValid(KernelSupport.parseHex(slide));
        append("[诊断] " + (usable
                ? "slide_probe 实测可用（slide=" + slide + "）——环境可用于提权"
                : "slide_probe 未拿到 slide，环境当前不可用"));
        String message = usable ? "诊断通过 · 环境可用" : "诊断未通过 · 详见日志";
        status(message);
        callbacks.onState(state, message);
    }

    private void runKernelSuStep() {
        try {
            step(6);
            status("已获得临时 ROOT · 正在加载 KernelSU");
            run(BootGuard.markCommand("ksu"), true);
            stageKsudIfNeeded();
            CommandResult load = run("rm -f /data/local/tmp/ksu_try.log; "
                    + "r=$(uname -r); "
                    + "a=$(echo \"$r\" | sed -n 's/.*\\(android[0-9][0-9]*\\).*/\\1/p'); "
                    + "k=$(echo \"$r\" | cut -d. -f1,2); "
                    + "kmi=\"${a:-android17}-${k:-6.18}\"; "
                    + "echo \"kmi=$kmi (from $r)\" >> /data/local/tmp/ksu_try.log; "
                    + SU_CLIENT + " -c \"cd /data/local/tmp && ./ksud late-load --kmi $kmi --allow-shell --package-name me.weishu.kernelsu\" "
                    + ">> /data/local/tmp/ksu_try.log 2>&1; echo rc=$? >> /data/local/tmp/ksu_try.log; "
                    + "su_out=\"\"; "
                    + "for i in 1 2 3 4 5 6 7 8 9 10; do "
                    + "  su_out=$(/system/bin/su -c id 2>&1); "
                    + "  echo \"$su_out\" | grep -q 'uid=0' && { echo \"$su_out\" >> /data/local/tmp/ksu_try.log; break; }; "
                    + "  sleep 0.3; "
                    + "done; "
                    + "ksud_v=$(/system/bin/su -c '/data/local/tmp/ksud -V' 2>/dev/null); "
                    + "enf=$(getenforce 2>/dev/null); "
                    + BootGuard.clearStageCommand() + "; "
                    + "echo \"__SU__=$su_out\"; "
                    + "echo \"__KSUD_V__=$ksud_v\"; "
                    + "echo \"__ENFORCE__=$enf\"; "
                    + "echo \"__LOG__\"; "
                    + "cat /data/local/tmp/ksu_try.log 2>/dev/null", true);
            String raw = load.output;
            int logMarker = raw.indexOf("__LOG__\n");
            String meta = logMarker >= 0 ? raw.substring(0, logMarker) : raw;
            String log = logMarker >= 0 ? raw.substring(logMarker + 8) : raw;
            if (!log.trim().isEmpty()) {
                append(log);
            }
            String suOut = extractKv(meta, "__SU__=");
            String ksudV = extractKv(meta, "__KSUD_V__=");
            String enf = extractKv(meta, "__ENFORCE__=");
            append("[KSU] su -c id → " + oneLine(suOut));
            append("[KSU] ksud -V → " + oneLine(ksudV));
            selinuxAfterRoot = enf.isEmpty() ? enforceNow() : enf;
            append("[SELinux] 最终实测 " + selinuxAfterRoot);
            if (suOut.contains("uid=0")) {
                run(BootGuard.suKillCommand(), true);
                append("[清理] 临时 rootd 已请求收尾（socket unlink 不会终止监听者，必须按 pgid 发信号）");
                state = State.COMPLETE;
                callbacks.onState(State.COMPLETE, "全部完成 · 已接管 · SELinux " + selinuxAfterRoot);
            } else {
                state = State.KSU_PENDING;
                callbacks.onState(State.KSU_PENDING,
                        "未接管 · 临时 ROOT 仍有效 · SELinux " + selinuxAfterRoot);
            }
        } catch (Throwable failure) {
            append(friendly(failure));
            if (shizukuGone()) {
                state = State.KSU_PENDING;
                callbacks.onState(State.KSU_PENDING,
                        "可能已接管 · Shizuku 已断开，请重新启动 Shizuku 后再确认 · SELinux " + selinuxAfterRoot);
                return;
            }
            if (isPanic()) {
                state = State.FAILED;
                callbacks.onState(State.FAILED, "内核已 panic（pstore 有记录），必须重启后再试");
                return;
            }
            state = State.KSU_PENDING;
            callbacks.onState(State.KSU_PENDING,
                    "未接管 · 临时 ROOT 仍有效 · SELinux " + selinuxAfterRoot);
        }
    }

    private void stageKsudIfNeeded() {
        try {
            CommandResult size = run("stat -c %s " + KSUD_FILE + " 2>/dev/null || echo 0", true);
            long remote;
            try {
                remote = Long.parseLong(size.output.trim());
            } catch (NumberFormatException ignored) {
                remote = -1L;
            }
            if (remote > 1000000L) {
                append("[部署] ksud 已在设备上（" + remote + " 字节），跳过传输");
                return;
            }
            deployer.stage("ksud");
        } catch (Exception error) {
            append("[部署] ksud 预检失败，改为重新投放：" + error.getMessage());
            try {
                deployer.stage("ksud");
            } catch (Exception fatal) {
                append("[部署] ksud 投放失败：" + fatal.getMessage());
            }
        }
    }

    private void waitForIdle() throws Exception {
        long started = System.currentTimeMillis();
        int runnable = -1;
        long freeKb = -1;
        long availableKb = -1;
        boolean reached = false;
        while (System.currentTimeMillis() - started < 20000L) {
            String[] dump = run("cat /proc/loadavg 2>/dev/null; grep -E '^(MemFree|MemAvailable):' /proc/meminfo 2>/dev/null", true)
                    .output.trim().split("\\n");
            for (String line : dump) {
                String[] fields = line.trim().split("\\s+");
                if (fields.length >= 4 && fields[3].contains("/")) {
                    try {
                        runnable = Integer.parseInt(fields[3].substring(0, fields[3].indexOf('/')));
                    } catch (NumberFormatException ignored) {
                        runnable = -1;
                    }
                } else if (fields.length >= 2) {
                    try {
                        if (fields[0].startsWith("MemFree")) {
                            freeKb = Long.parseLong(fields[1]);
                        } else if (fields[0].startsWith("MemAvailable")) {
                            availableKb = Long.parseLong(fields[1]);
                        }
                    } catch (NumberFormatException ignored) {
                        // keep the previous sample
                    }
                }
            }
            if (runnable >= 0 && runnable <= 6 && availableKb >= IDLE_AVAILABLE_KB) {
                reached = true;
                break;
            }
            Thread.sleep(300L);
        }
        append(String.format(Locale.US,
                "[空闲] 等待 %.1fs · runnable=%d · MemAvailable=%d kB（门限 %d）· MemFree=%d kB · %s",
                (System.currentTimeMillis() - started) / 1000.0, runnable, availableKb, IDLE_AVAILABLE_KB,
                freeKb, reached ? "达标，开跑" : "未达标，仍开跑"));
    }

    private String measureAddress(String boot) throws Exception {
        if (boot != null && !boot.isEmpty()) {
            String cached = run("cat " + BootGuard.SLIDE_CACHE_FILE + " 2>/dev/null", true).output.trim();
            String[] parts = cached.split("\\s+");
            if (parts.length == 3 && boot.equals(parts[0])) {
                if ("slide".equals(parts[1]) && KernelSupport.isSlideValid(KernelSupport.parseHex(parts[2]))) {
                    append("slide = " + parts[2] + "（同开机缓存命中，跳过 slide_probe）");
                    return "--slide " + parts[2];
                }
                if ("site".equals(parts[1]) && parts[2].startsWith("0x")) {
                    append("site = " + parts[2] + "（同开机缓存命中，跳过 slide_probe）");
                    return "--site " + parts[2];
                }
            }
        }

        long begin = System.currentTimeMillis();
        run(BootGuard.markCommand("probe-slide"), true);
        CommandResult probe = run(BootGuard.withTimeout(SLIDE_PROBE_TIMEOUT_S,
                "/data/local/tmp/slide_probe"), false);
        append(filterProbe(probe.output));
        append(String.format(Locale.US, "[耗时] slide_probe %.1fs",
                (System.currentTimeMillis() - begin) / 1000.0));
        if (probe.exitCode == BootGuard.TIMEOUT_EXIT) {
            append("slide_probe 超过 " + SLIDE_PROBE_TIMEOUT_S + " 秒被 timeout 终止");
        }

        String slide = KernelSupport.extractSlide(probe.output);
        if (slide != null && KernelSupport.isSlideValid(KernelSupport.parseHex(slide))) {
            append("slide = " + slide + "（slide_probe）");
            cacheAddress(boot, "slide", slide);
            return "--slide " + slide;
        }
        String site = KernelSupport.extractSite(probe.output);
        if (site != null) {
            append("site = " + site + "（slide_probe）");
            cacheAddress(boot, "site", site);
            return "--site " + site;
        }

        append("[测量] slide_probe 未给出可用地址（输出里没有 slide=/site=）");
        append("[测量] 改为不带参数运行，让 uaf_plant_replay 用 profile 自行判定。");
        return "";
    }

    private void cacheAddress(String boot, String kind, String value) {
        if (boot == null || boot.isEmpty()) {
            return;
        }
        try {
            run("echo '" + boot + " " + kind + " " + value + "' > " + BootGuard.SLIDE_CACHE_FILE, true);
        } catch (Exception ignored) {
            // Cache failure must not block the workflow.
        }
    }

    /**
     * Runs the payload up to three times.
     *
     * @return null on success; otherwise a message to show. An empty message means "plain failure"
     *         (the caller records it), a non-empty one is a fatal condition already recorded here.
     */
    private String runPayload(String addressArgument, String boot) throws Exception {
        String args = addressArgument == null ? "" : addressArgument.trim();
        if (!args.isEmpty()) {
            append("[payload] 参数：" + args);
        } else {
            append("[payload] 不带地址参数启动（由 payload 自行判定）");
        }
        payloadLines.clear();
        int misses = 0;
        for (int attempt = 1; attempt <= 3; attempt++) {
            payloadStartAt = System.currentTimeMillis();
            run("rm -f /data/local/tmp/uaf_replay.log; " + BootGuard.launchCommand(
                    "/data/local/tmp/uaf_plant_replay",
                    args,
                    "/data/local/tmp/uaf_replay.log"), true);
            Thread.sleep(400L);
            boolean exited = false;
            for (int poll = 0; poll < 200; poll++) {
                String snap = run(
                        "echo \"__SOCK__=$([ -S " + ROOTD_SOCKET + " ] && echo 1 || echo 0)\"; "
                        + "echo \"__ALIVE__=$(" + BootGuard.aliveCommand() + ")\"; "
                        + "echo \"__TAIL__\"; "
                        + "tail -n 24 /data/local/tmp/uaf_replay.log 2>/dev/null", true).output;
                int tailIdx = snap.indexOf("__TAIL__\n");
                String header = tailIdx >= 0 ? snap.substring(0, tailIdx) : snap;
                String tail = tailIdx >= 0 ? snap.substring(tailIdx + 9) : "";
                boolean sockReady = "1".equals(extractKv(header, "__SOCK__="));
                boolean alive = !"0".equals(extractKv(header, "__ALIVE__="));
                if (!tail.trim().isEmpty()) {
                    callbacks.onTail(tail);
                    appendPayloadOutput(tail);
                }
                BootGuard.Outcome outcome = BootGuard.classify(tail);
                if (outcome == BootGuard.Outcome.SUCCESS) {
                    append(String.format(Locale.US, "[耗时] payload 成功，总耗时 %.1fs（本轮第 %d 次尝试，累计未命中 %d 次）",
                            payloadElapsed(), attempt, misses));
                    return null;
                }
                if (outcome == BootGuard.Outcome.ABORT_BOOT) {
                    run(BootGuard.recordFailureCommand(boot, true, false), true);
                    return "payload 报告节点已挂树（holding zombie）· 本次开机禁止重跑，请重启设备";
                }
                if (sockReady || tail.contains("[rootd]")) {
                    CommandResult verify = run(SU_CLIENT + " -c 'id'", true);
                    if (isRoot(verify.output)) {
                        append(String.format(Locale.US, "[耗时] payload 成功，总耗时 %.1fs（第 %d 次尝试，累计未命中 %d 次）",
                                payloadElapsed(), attempt, misses));
                        return null;
                    }
                }
                if (outcome == BootGuard.Outcome.RETRY_SAFE) {
                    break;
                }
                if (!alive) {
                    exited = true;
                    break;
                }
                Thread.sleep(500L);
            }
            if (exited) {
                String tail = run("cat /data/local/tmp/uaf_replay.log 2>/dev/null", true).output;
                appendPayloadOutput(tail);
                if (tail.trim().isEmpty()) {
                    append("[payload] 进程已退出且日志为空");
                }
                BootGuard.Outcome postOutcome = BootGuard.classify(tail);
                if (postOutcome == BootGuard.Outcome.ABORT_BOOT) {
                    run(BootGuard.recordFailureCommand(boot, true, false), true);
                    return "payload 报告节点已挂树（holding zombie）· 本次开机禁止重跑，请重启设备";
                }
                recordFailedBoot(boot, false);
                return "payload 提前退出（未进入提权阶段）· 详见上方输出";
            }
            misses++;
            append(String.format(Locale.US, "[重试] 第 %d 次未命中（本轮耗时 %.1fs），重启 payload 再试（%d/3）",
                    attempt, payloadElapsed(), attempt + 1));
            if (attempt < 3) {
                stopPayload();
                Thread.sleep(1000L);
            }
        }
        return isRoot(run(SU_CLIENT + " -c 'id'", true).output) ? null : "";
    }

    private boolean socketExists() throws Exception {
        return "1".equals(run("test -S " + ROOTD_SOCKET + " && echo 1 || echo 0", true).output.trim());
    }

    private void stopPayload() throws Exception {
        run(BootGuard.killCommand(), true);
    }

    private int payloadProcessCount() throws Exception {
        int count = Integer.parseInt(run(BootGuard.aliveCommand(), true).output.trim());
        if (count > 0) {
            return count;
        }
        return socketExists() ? 1 : 0;
    }

    private void cleanupBinaries(boolean keepRootClient) {
        try {
            if (!keepRootClient) {
                run(BootGuard.killCommand(), true);
            }
            String targets = EXPLOIT_BINARIES
                    + (keepRootClient ? "" : " pc98260-su pc98260-root.sock");
            run("cd /data/local/tmp 2>/dev/null; rm -f " + targets + "; true", true);
            String reason;
            if (keepRootClient) {
                reason = "（保留 pc98260-su、rootd socket 与 ksud，临时 ROOT 仍在用）";
            } else if (state == State.COMPLETE) {
                reason = "（KernelSU 已接管，临时通道一并移除；ksud 保留备用）";
            } else {
                reason = "（本次运行未成功，临时产物一并移除；ksud 保留备用）";
            }
            append("[清理] 已移除 " + targets + reason);
        } catch (Exception ignored) {
            // Cleanup is best effort and must not change the workflow result.
        }
    }

    public boolean runMaintenance(String command) {
        return start("maint", () -> {
            boolean canElevate = "yes".equals(run("test -x /system/bin/su && echo yes || echo no", true).output.trim());
            String target = command;
            if (command.contains("pidof system_server")) {
                if (!canElevate) {
                    append("[维护] 软重启需要 /system/bin/su（KernelSU 已加载后可用），当前不可用");
                    callbacks.onState(state, "软重启不可用 · 需要 KernelSU su");
                    return;
                }
                target = "/system/bin/su -c 'stop; start'";
                append("[维护] 软重启：完整框架重启（zygote 重新拉起，Zygisk/LSPosed 会重新注入）");
            } else if (command.startsWith("reboot") && canElevate) {
                target = "/system/bin/su -c 'reboot'";
            }
            CommandResult result = run(target, true);
            append(result.isSuccess()
                    ? "维护命令完成"
                    : "维护命令失败（退出码 " + result.exitCode + "）：" + result.output);
        }, false);
    }

    private CommandResult run(String command, boolean quiet) throws Exception {
        return executor.run(command, quiet);
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

    private void recordFailedBoot(String boot, boolean abort) {
        if (boot == null || boot.isEmpty()) {
            return;
        }
        try {
            boolean permissive = "Permissive".equalsIgnoreCase(run("getenforce 2>/dev/null", true).output.trim());
            run(BootGuard.recordFailureCommand(boot, abort, permissive), true);
            if (abort) {
                append("已记录：本次开机节点已挂树，禁止重跑，请重启设备后再试。");
            } else {
                append(permissive
                        ? "已记录本次失败：SELinux 已 Permissive，可直接重试 cred 阶段（无需重启）。"
                        : "已记录本次失败：SELinux 仍 Enforcing，请重启后重试，切勿重复点击。");
            }
        } catch (Exception ignored) {
            // Recording the failure must never mask the original error.
        }
    }

    private void cleanMemory() {
        try {
            long[] before = memoryState();
            if (before[1] >= CLEAN_SKIP_AVAILABLE_KB) {
                append("清理系统内存：跳过（MemAvailable " + before[1] + " kB 已超过 "
                        + CLEAN_SKIP_AVAILABLE_KB + " kB，无需中断后台应用）");
                return;
            }
            CommandResult stop = run("am force-stop com.tencent.mm 2>/dev/null; am force-stop com.tencent.mobileqq 2>/dev/null; true", true);
            long[] after = memoryState();
            append("清理系统内存：MemFree " + before[0] + "→" + after[0] + " kB · MemAvailable "
                    + before[1] + "→" + after[1] + " kB"
                    + (stop.exitCode == 0 ? "" : "（命令退出码 " + stop.exitCode + "）"));
        } catch (Exception ignored) {
            append("清理系统内存：跳过");
        }
    }

    private long[] memoryState() {
        try {
            String out = run("grep -E '^(MemFree|MemAvailable):' /proc/meminfo 2>/dev/null", true).output.trim();
            long free = -1L;
            long available = -1L;
            for (String line : out.split("\\n")) {
                String[] fields = line.trim().split("\\s+");
                if (fields.length < 2) {
                    continue;
                }
                if (fields[0].startsWith("MemFree")) {
                    free = Long.parseLong(fields[1]);
                } else if (fields[0].startsWith("MemAvailable")) {
                    available = Long.parseLong(fields[1]);
                }
            }
            return new long[]{free, available};
        } catch (Exception ignored) {
            return new long[]{-1L, -1L};
        }
    }

    private Map<String, String> fetchPreflightSnapshot() throws Exception {
        String cmd = "echo \"UNAME=$(uname -r 2>/dev/null)\"; "
                + "echo \"BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)\"; "
                + "echo \"ID=$(id 2>/dev/null)\"; "
                + "echo \"ENFORCE=$(getenforce 2>/dev/null)\"; "
                + "echo \"PATCH=$(getprop ro.build.version.security_patch 2>/dev/null)\"; "
                + "if [ -x /system/bin/su ]; then echo \"SU=$(/system/bin/su -c id 2>/dev/null)\"; else echo \"SU=\"; fi; "
                + "echo \"SOCK=$(ls -l " + ROOTD_SOCKET + " 2>/dev/null)\"; "
                + "echo \"STAGE=$(cat " + BootGuard.STAGE_FILE + " 2>/dev/null)\"; "
                + "echo \"FAILED=$(cat " + BootGuard.FAILED_FILE + " 2>/dev/null)\"";
        String out = run(cmd, false).output;
        Map<String, String> map = new HashMap<>();
        for (String line : out.split("\\n")) {
            int eq = line.indexOf('=');
            if (eq > 0) {
                map.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
            }
        }
        return map;
    }

    private static String extractKv(String text, String prefix) {
        for (String line : text.split("\\n")) {
            if (line.startsWith(prefix)) {
                return line.substring(prefix.length()).trim();
            }
        }
        return "";
    }

    private void applyBaseline(Map<String, String> preflight) {
        try {
            String id = oneLine(preflight.getOrDefault("ID", ""));
            enforceBeforeRun = preflight.getOrDefault("ENFORCE", "");
            String patch = preflight.getOrDefault("PATCH", "");
            String suProbe = preflight.getOrDefault("SU", "");
            String socket = preflight.getOrDefault("SOCK", "");
            append("[基线] id=" + id + " · SELinux=" + enforceBeforeRun);
            append("[基线] security_patch=" + (patch.isEmpty() ? "未知" : patch)
                    + (patch.isEmpty() ? "" : (patch.compareTo("2026-10-06") < 0
                    ? "（早于上游修复 2026-10-06，处于未修补窗口）"
                    : "（不早于上游修复 2026-10-06，固件可能已回补，失败需先怀疑此处）")));
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
