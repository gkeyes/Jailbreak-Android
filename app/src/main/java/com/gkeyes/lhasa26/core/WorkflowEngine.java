package com.gkeyes.lhasa26.core;

import android.content.res.AssetManager;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
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
    public enum State { IDLE, RUNNING, ROOTED, KSU_PENDING, COMPLETE, FAILED, PARKED }

    public static final String[] STEP_LABELS = {
            "校验内核", "部署程序", "测量内核地址", "等待系统空闲",
            "提权执行", "结果验证", "KernelSU 接管"
    };

    /**
     * 99491（CVE-2026-99491 real_cred 链）的步骤标签。
     *
     * <p>按路径分开，UI 的进度条文案随路径变化；98260 继续用上面的 {@link #STEP_LABELS}，
     * 一个字都不改。两套长度一致（7 步），{@link #onStep} 的下标语义保持兼容。
     */
    public static final String[] STEP_LABELS_99491 = {
            "校验 profile", "部署资产", "预检", "KASLR anchor",
            "real_cred 写原语", "SELinux 切换", "KernelSU 接管"
    };

    private static final long IDLE_AVAILABLE_KB = 1500000L;
    private static final long CLEAN_SKIP_AVAILABLE_KB = 3000000L;
    private static final long DEPLOY_TIMEOUT_MS = 8000L;
    private static final long DEPLOY_JOIN_MS = 1500L;
    private static final int TEMP_ROOT_PROBE_TIMEOUT_S = 3;
    /** ksud 的权威大小（tools/assets-ledger.json）；不一致就重新投放。 */
    private static final long KSUD_BYTES = AssetIntegrity.KSUD_BYTES;
    private static final String RUN_MARKER = "/data/local/tmp/.lhasa_run";
    private static final String ROOTD_SOCKET = "/data/local/tmp/pc98260-root.sock";
    private static final String SU_CLIENT = "/data/local/tmp/pc98260-su";
    private static final String KSUD_FILE = "/data/local/tmp/ksud";
    private static final String EXPLOIT_BINARIES = "uaf_plant_replay slide_probe reach_probe cve99491_exp";
    private static final int SLIDE_PROBE_TIMEOUT_S = 12;
    private static final int DIAGNOSE_TIMEOUT_S = 25;
    /**
     * 99491 链部署超时：exp + profile + ko(375 KB) + ksud(4.9 MB，远端已校验时跳过) 经 Shizuku
     * 管道投放；按路径可配置（docs/99491-test-plan.md §4）。
     */
    private static final long CVE99491_DEPLOY_TIMEOUT_MS = 60000L;
    /**
     * 99491 direct 引擎整体上限：cred 泄漏/UAF 写/窗口/60s 模块 Live 轮询都在里面，
     * 用异步 launch + 轮询（不受 CommandExecutor 单命令 120s 上限约束）。
     */
    private static final long CVE99491_RUN_TIMEOUT_MS = 240000L;
    private static final long CVE99491_POLL_MS = 400L;
    /** 99491 工作目录：exp/profile/运行时标记都在这里（ext 用相对路径 ./…）。 */
    private static final String CVE99491_DIR = AssetDeployer.CVE99491_DIR;
    private static final String CVE99491_BINARY = CVE99491_DIR + "/" + AssetIntegrity.CVE99491_EXP_ASSET;
    private static final String CVE99491_RUN_LOG = "/data/local/tmp/cve99491_run.log";
    private static final String CVE99491_KSU_KO = "/data/local/tmp/" + AssetIntegrity.KSU_KO_ASSET;
    private final AssetManager assets;
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
    private volatile long payloadStartAt;
    private volatile String mirroredStage = "";
    private volatile State state = State.IDLE;
    private volatile long startedAt;
    private volatile int currentStep = -1;
    private volatile boolean busy;
    private volatile boolean rootBeforeRun;
    private volatile String enforceBeforeRun = "";
    private volatile String selinuxAfterRoot = "?";
    private volatile long lastDeviceRefresh;
    /** 用户选择的路径（持久化值）；运行中被分派链使用。 */
    private volatile RootPath rootPath = RootPath.DEFAULT;
    /** 本次实际执行的路径；发生 98260 回退后会变成 TIMER_98260，日志导出靠它归因。 */
    private volatile RootPath activePath = RootPath.DEFAULT;
    /** 最近一次 99491 profile 可用性判定（fail-closed，null 表示还没校验过）。 */
    private volatile Cve99491Profile.Status cve99491Status;
    /** debug 构建允许 verified=0 的 profile 带警告运行（真机标定用）；release 恒 false。 */
    private volatile boolean unverifiedProfileAllowed;
    private volatile long chainElapsedMs;
    private volatile String lastStepLabel = "";

    public WorkflowEngine(AssetManager assets, CommandExecutor executor, WorkflowCallbacks callbacks) {
        this.assets = assets;
        this.executor = executor;
        this.callbacks = callbacks;
        this.deployer = new AssetDeployer(assets, executor, this);
    }

    public State getState() {
        return state;
    }

    /** 用户选择的提权路径（默认 98260）。 */
    public RootPath getRootPath() {
        return rootPath;
    }

    /** 宿主切换路径；只影响下一次运行，不打断正在跑的任务。 */
    public void setRootPath(RootPath path) {
        if (path != null) {
            rootPath = path;
        }
    }

    /** 本次实际执行的路径；99491 写前失败自动回退后为 TIMER_98260。 */
    public RootPath getActivePath() {
        return activePath;
    }

    /** 最近一次 99491 profile 可用性判定；还未校验时为 null（UI 按不可用处理）。 */
    public Cve99491Profile.Status getCve99491Status() {
        return cve99491Status;
    }

    /**
     * debug 构建允许 verified=0 的 profile 带警告运行（真机标定阶段）。
     *
     * <p>release 构建绝不能打开：宿主用 {@code ApplicationInfo.FLAG_DEBUGGABLE} 判断后传入。
     */
    public void setUnverifiedProfileAllowed(boolean allowed) {
        unverifiedProfileAllowed = allowed;
    }

    public boolean isUnverifiedProfileAllowed() {
        return unverifiedProfileAllowed;
    }

    /** 最近一次读取到的 profile sha256；98260 或未校验时为空串。 */
    public String getProfileSha256() {
        Cve99491Profile.Status status = cve99491Status;
        return status == null || status.sha256 == null ? "" : status.sha256;
    }

    /** 最近一次完整链路的耗时（从点击到结束/失败），日志导出用。 */
    public long getChainElapsedMs() {
        return chainElapsedMs;
    }

    /** 最近一次推进到的步骤标签，日志导出/状态同步用。 */
    public String getLastStepLabel() {
        return lastStepLabel;
    }

    /** 按路径取步骤标签（防御性拷贝，调用方改不动常量表）。 */
    public static String[] stepLabels(RootPath path) {
        if (path == RootPath.WACOM_99491) {
            return STEP_LABELS_99491.clone();
        }
        return STEP_LABELS.clone();
    }

    /** 部署超时按路径可配置：99491 的资产更大，放宽到 {@link #CVE99491_DEPLOY_TIMEOUT_MS}。 */
    public static long deployTimeoutMs(RootPath path) {
        return path == RootPath.WACOM_99491 ? CVE99491_DEPLOY_TIMEOUT_MS : DEPLOY_TIMEOUT_MS;
    }

    /**
     * 99491 的最终设备命令（Lead 真机验收通过的形态）。
     *
     * <p>`CVE99491_KSU_BACKEND=ko`（KO 直载后端，失败不回退 cli）、`CVE99491_KSUD_BIN`/
     * `CVE99491_KSU_KO` 指向已校验的资产、`CVE99491_TIMING=1` 打时间戳；`--stage=root` 做
     * cred+fsuid+caps+permissive+KO 载入+su 验收。相对路径依赖 cwd = {@link #CVE99491_DIR}。
     *
     * <p>公开成静态方法是为了让 JVM 单测能锁住 env/参数，防止以后改坏。
     */
    public static String cve99491RunCommand() {
        return "cd " + CVE99491_DIR
                + " && env CVE99491_KSU_BACKEND=ko"
                + " CVE99491_KSUD_BIN=" + KSUD_FILE
                + " CVE99491_KSU_KO=" + CVE99491_KSU_KO
                + " CVE99491_TIMING=1"
                + " ./" + AssetIntegrity.CVE99491_EXP_ASSET
                + " --stage=root --profile ./" + Cve99491Profile.ASSET_NAME
                + " --workdir .";
    }

    /** 99491 工作目录（单测/日志用）。 */
    public static String cve99491WorkDir() {
        return CVE99491_DIR;
    }

    /** 99491 期望的 KO 路径（单测/日志用）。 */
    public static String cve99491KsuKoPath() {
        return CVE99491_KSU_KO;
    }

    public boolean startRoot() {
        return start("root", this::runSelectedRootChain, true);
    }

    /** 按当前选择分派；99491 的写前失败会自动回退到 98260（D4）。 */
    private void runSelectedRootChain() throws Exception {
        if (rootPath == RootPath.WACOM_99491) {
            activePath = RootPath.WACOM_99491;
            append(RootPath.WACOM_99491.channel() + " 路径选择：" + RootPath.WACOM_99491.label()
                    + "（CVE-2026-99491，opt-in）");
            runCve99491Chain();
            return;
        }
        activePath = RootPath.TIMER_98260;
        runRootChain();
    }

    /**
     * 异步校验 99491 profile 的可用性（release 精确匹配 + verified）。
     *
     * <p>fail-closed：资产缺失、JSON 损坏、设备内核读不到、release 不匹配、未 verified 都判不可用。
     * 结果通过 {@link WorkflowCallbacks#onRootPathAvailability(boolean, String)} 回给宿主。
     */
    public void refreshRootPathAvailability() {
        try {
            worker.execute(() -> {
                Cve99491Profile.Status status;
                try {
                    status = evaluateCve99491Status();
                } catch (Throwable error) {
                    status = Cve99491Profile.check("", null);
                }
                cve99491Status = status;
                try {
                    callbacks.onRootPathAvailability(status.available, status.reason);
                } catch (Throwable ignored) {
                    // UI 回调失败不能影响主流程。
                }
            });
        } catch (RuntimeException ignored) {
            // worker 已关闭（应用退出中），忽略。
        }
    }

    private Cve99491Profile.Status evaluateCve99491Status() {
        String release = "";
        if (executor.isAvailable()) {
            try {
                release = run("uname -r", true).output.trim();
            } catch (Throwable ignored) {
                release = "";
            }
        }
        return Cve99491Profile.check(release, readAsset(Cve99491Profile.ASSET_NAME),
                unverifiedProfileAllowed);
    }

    /** 读 APK 内资产；不存在/读失败返回 null（交给 Cve99491Profile 变成明确错误）。 */
    private byte[] readAsset(String name) {
        try (InputStream input = assets.open(name)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    output.write(buffer, 0, count);
                }
            }
            return output.toByteArray();
        } catch (Throwable ignored) {
            return null;
        }
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
        deployer.cancel();
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

    private double payloadElapsed() {
        long start = payloadStartAt;
        if (start <= 0L) {
            return 0.0;
        }
        return (System.currentTimeMillis() - start) / 1000.0;
    }

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

    /** 把 payload 最新子阶段写进面包屑；硬重启后靠它定位。只在阶段变化时写。 */
    private void mirrorPayloadStage(String tail) {
        if (tail == null || tail.isEmpty()) {
            return;
        }
        String stage = null;
        for (String raw : tail.split("\\n")) {
            String line = raw.trim();
            if (line.isEmpty()) {
                continue;
            }
            if (line.startsWith("[rootd]")) {
                stage = "payload-rootd";
            } else if (line.startsWith("[cred] REAL_") || line.startsWith("[cred] installed")
                    || line.startsWith("[child-cred]")) {
                stage = "payload-cred-finish";
            } else if (line.startsWith("[cred] plant attempt ")) {
                stage = "payload-cred-" + attemptNumber(line);
            } else if (line.startsWith("[selinux] already")) {
                stage = "payload-selinux-done";
            } else if (line.startsWith("[selinux] attempt ")) {
                stage = "payload-selinux-" + attemptNumber(line);
            } else if (line.startsWith("[uaf] page miss")) {
                stage = "payload-miss";
            } else if (line.startsWith("[exec]")) {
                stage = "payload-exec";
            } else if (line.startsWith("[stream] writes=")) {
                stage = "payload-stream";
            } else if (line.startsWith("[task] ok")) {
                stage = "payload-task-ok";
            }
        }
        if (stage == null || stage.equals(mirroredStage)) {
            return;
        }
        mirroredStage = stage;
        try {
            run(BootGuard.markCommand(stage), true);
        } catch (Exception ignored) {
            // 面包屑写失败不该影响主流程
        }
    }

    private static String attemptNumber(String line) {
        int idx = line.indexOf("attempt ");
        if (idx < 0) {
            return "0";
        }
        String rest = line.substring(idx + "attempt ".length());
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c >= '0' && c <= '9') {
                digits.append(c);
            } else {
                break;
            }
        }
        return digits.length() == 0 ? "0" : digits.toString();
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
            chainElapsedMs = 0L;
            lastStepLabel = "";
            if (ownsState) {
                state = State.RUNNING;
                synchronized (logLock) {
                    sessionLog.setLength(0);
                }
                payloadLines.clear();
                payloadStartAt = 0L;
                mirroredStage = "";
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
                    chainElapsedMs = System.currentTimeMillis() - startedAt;
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
            // 注意：仍在运行中，接管结束后才发 COMPLETE；这里先给 RUNNING 让 UI 保持计时。
            callbacks.onState(State.RUNNING, "复用已有临时 ROOT · 正在接管 KernelSU");
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
            // 99491 链留下的 dirty 记录（dirty99491/parked99491）对 98260 同样生效：
            // 两条链共享 dirty 标记，但错误信息要按路径说清楚。
            String sharedDirty = BootGuard.dirtyReason(recorded, boot);
            if (sharedDirty.contains("99491")) {
                throw new IllegalStateException("[98260] " + sharedDirty + "。请重启设备后再试。");
            }
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
            // 先真正停掉写入，确认线程退出，再进入失败清理——否则旧任务会在清理之后把文件写回去。
            deployer.cancel();
            deploy.interrupt();
            try {
                deploy.join(DEPLOY_JOIN_MS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            if (deploy.isAlive()) {
                append("[部署] 取消后部署线程仍未退出——本轮不再继续，请重启设备后再试");
            } else {
                append("[部署] 已取消，并确认部署线程退出");
            }
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

    // ---- 99491（CVE-2026-99491 real_cred）链 ----

    /**
     * 99491 链：部署资产 → 预检 → 运行分阶段二进制 → 解析标记 → 接管 KernelSU。
     *
     * <p>失败处置严格按 D4：只有"零内核写之前"失败允许自动回退 98260；写后失败置 dirty boot
     * 并要求重启；PARKED 则本 boot 不再写、也不回退。两条链共享同一个 dirty 标记文件。
     * 98260 的逻辑不在这里，{@link #runRootChain()} 保持原样。
     */
    private void runCve99491Chain() throws Exception {
        String channel = RootPath.WACOM_99491.channel();
        activePath = RootPath.WACOM_99491;
        step(0);
        status(channel + " 校验 profile / 干净开机预检");
        Map<String, String> preflight = fetchPreflightSnapshot();
        String kernel = preflight.getOrDefault("UNAME", "");
        String boot = preflight.getOrDefault("BOOT", "");
        String recorded = preflight.getOrDefault("FAILED", "").trim();
        String modules = preflight.getOrDefault("MODULES", "");
        enforceBeforeRun = preflight.getOrDefault("ENFORCE", "");
        String identity = oneLine(preflight.getOrDefault("ID", ""));
        rootBeforeRun = preflight.getOrDefault("SU", "").contains("uid=0") || identity.contains("uid=0");
        append(channel + " [基线] id=" + identity + " · SELinux=" + enforceBeforeRun);
        append(channel + " uname -r = " + kernel);
        if (!BootGuard.isSupportedKernel(kernel)) {
            append(channel + " " + BootGuard.kernelWarning(kernel));
        }
        String hint = BootGuard.leftoverStageHint(preflight.getOrDefault("STAGE", ""));
        if (!hint.isEmpty()) {
            append(channel + " [上次] " + hint);
        }

        // 1) 干净开机预检（Lead 最终流程硬要求）：非 Enforcing 或 /proc/modules 已有 kernelsu → 拒绝重启。
        //    /sys/module/kernelsu 作为第二来源（部分 ROM 上 shell 读不到 /proc/modules）。
        String ksuModuleDir = preflight.getOrDefault("KSUDIR", "").trim();
        String refusal = BootGuard.cleanBootRefusal(enforceBeforeRun, modules, !ksuModuleDir.isEmpty());
        if (!refusal.isEmpty()) {
            append(channel + " [预检] " + refusal);
            throw new IllegalStateException(channel + " " + refusal);
        }
        // 2) 已由 KernelSU 接管（su 可用）：无需执行；clean boot 检查已覆盖"模块 Live"的常态。
        if (rootBeforeRun) {
            clearRunMarker();
            run(BootGuard.clearStageCommand(), true);
            state = State.COMPLETE;
            selinuxAfterRoot = enforceNow();
            append(channel + " [跳过] 检测到 su 已可用且为 uid=0 —— 本机已由 KernelSU 接管。");
            append(channel + " [跳过] 不再执行 99491；如需重新验证请先重启设备。");
            callbacks.onState(State.COMPLETE,
                    "99491 无需执行：已由 KernelSU 接管 · SELinux " + selinuxAfterRoot);
            return;
        }
        // 3) 两条链共享的 dirty 标记（任一条写后失败都不许在本 boot 再写）。
        String dirty = BootGuard.dirtyReason(recorded, boot);
        if (!dirty.isEmpty()) {
            throw new IllegalStateException(channel + " " + dirty + " · 本 boot 禁止再写内核，请重启设备后再试");
        }
        if (payloadProcessCount() > 0) {
            throw new IllegalStateException(channel + " 上次运行的进程仍在运行，请重启设备后重试。");
        }
        // 4) profile 可用性：release 精确匹配 + verified。失败即 fail-closed，不运行任何二进制。
        Cve99491Profile.Status profileStatus = Cve99491Profile.check(
                kernel, readAsset(Cve99491Profile.ASSET_NAME), unverifiedProfileAllowed);
        cve99491Status = profileStatus;
        if (!profileStatus.available) {
            append(channel + " profile 不可用：" + profileStatus.reason);
            throw new IllegalStateException(channel + " 99491 profile 不可用（fail-closed，未写入内核）："
                    + profileStatus.reason);
        }
        append(channel + " [p] profile_ok release=" + profileStatus.release
                + " sha256=" + profileStatus.sha256 + " · " + profileStatus.reason);

        // 5) APK 资产存在性预检：缺件在开远端进程之前就报出来（零写 → 允许回退 98260）。
        List<String> missing = AssetDeployer.missingAssets(
                RootPath.WACOM_99491, listAssetNames());
        if (!missing.isEmpty()) {
            append(channel + " [预检] APK 缺少 99491 必需资产：" + missing);
            fallbackTo98260(channel + " 资产缺失（" + missing + "）");
            return;
        }

        // 6) 部署：exp/profile → /data/local/tmp/cve99491/，ko/ksud → /data/local/tmp/（带 size/sha256 校验）。
        writeRunMarker(boot);
        writeStageQuietly("99491-deploy");
        step(1);
        status(channel + " 部署资产（exp/profile/ko/ksud）");
        DeployGate deployed = deployAssets(RootPath.WACOM_99491,
                deployTimeoutMs(RootPath.WACOM_99491));
        if (deployed.outcome() != DeployGate.Result.READY) {
            boolean deployAlive = deployed.isWorkerAlive();
            append(channel + " [部署] 未就绪（" + deployed.outcome() + "）"
                    + (deployAlive ? "，部署线程仍存活" : "，线程已退出"));
            Throwable cause = deployed.failure();
            if (cause != null) {
                append(channel + " [部署] 原因：" + friendly(cause));
            }
            run(BootGuard.clearStageCommand(), true);
            if (deployAlive) {
                throw new IllegalStateException(channel + " 部署线程取消后仍未退出——禁止回退或继续，"
                        + "请重启设备后再试");
            }
            fallbackTo98260(channel + " 资产部署失败（" + deployed.outcome() + "）");
            return;
        }

        // 7) 运行 direct 引擎：--stage=root 一次做完 cred/fsuid/caps/SELinux 窗口/KO 载入/su 验收。
        step(2);
        status(channel + " 提权执行中（--stage=root，KO 后端），请勿中断");
        writeStageQuietly("99491-run");
        append(channel + " 运行（cwd=" + CVE99491_DIR + "）：" + cve99491RunCommand());
        CveRunResult runResult = runCve99491Binary(channel);
        String output = runResult.output;
        stepForCve99491Output(output);
        BootGuard.Cve99491Outcome outcome = BootGuard.classifyCve99491(output);
        append(channel + " 标记分类=" + outcome + (runResult.timedOut ? "（轮询超时）" : ""));
        if (outcome == BootGuard.Cve99491Outcome.SUCCESS) {
            boolean accepted = verifyCve99491Acceptance();
            boolean live = kernelSuModuleLiveNow();
            finishCve99491Success(channel, accepted, live);
            return;
        }
        RootPathDecision.Decision decision = RootPathDecision.decide(output, runResult.timedOut);
        append(channel + " 裁决=" + decision + " · " + RootPathDecision.describe(decision));
        if (decision == RootPathDecision.Decision.DIRTY_BOOT
                && BootGuard.hasCve99491ModuleLive(output) && verifyCve99491Acceptance()) {
            // 模块已 live 但二进制没打出最终 su_check 行：外部 su 验收通过就按成功处理，
            // 不把一个已接管的内核误标成 dirty（那会逼用户白重启一次）。
            finishCve99491Success(channel, true, true);
            return;
        }
        settleCve99491Failure(channel, decision, boot);
    }

    /** 99491 一次运行的输出与"是否因轮询超时被终止"。 */
    private static final class CveRunResult {
        final String output;
        final boolean timedOut;

        CveRunResult(String output, boolean timedOut) {
            this.output = output == null ? "" : output;
            this.timedOut = timedOut;
        }
    }

    /**
     * 异步启动 99491 direct 引擎并轮询日志。
     *
     * <p>为什么不用单条 `run()`：CommandExecutor 对单条远端命令有 120s 上限，而 --stage=root
     * 含 cred 泄漏/多次 UAF 写/60s 模块 Live 轮询，必须在 120s 内完成并不现实；launch+poll
     * 同时也能把实时 tail 喂给 UI（98260 的 payload 也是这个模式）。
     */
    private CveRunResult runCve99491Binary(String channel) throws Exception {
        payloadLines.clear();
        payloadStartAt = System.currentTimeMillis();
        run("rm -f " + CVE99491_RUN_LOG + "; "
                + BootGuard.launchCommand(cve99491RunCommand(), "", CVE99491_RUN_LOG), true);
        Thread.sleep(CVE99491_POLL_MS);
        long deadline = System.currentTimeMillis() + CVE99491_RUN_TIMEOUT_MS;
        boolean exited = false;
        while (System.currentTimeMillis() < deadline) {
            String snap = run("echo \"__ALIVE__=$(" + BootGuard.aliveCommand() + ")\"; "
                    + "echo \"__TAIL__\"; tail -n 40 " + CVE99491_RUN_LOG + " 2>/dev/null", true).output;
            int tailIdx = snap.indexOf("__TAIL__\n");
            String header = tailIdx >= 0 ? snap.substring(0, tailIdx) : snap;
            String tail = tailIdx >= 0 ? snap.substring(tailIdx + 9) : "";
            boolean alive = !"0".equals(extractKv(header, "__ALIVE__="));
            if (!tail.trim().isEmpty()) {
                callbacks.onTail(tail);
                appendCve99491Output(tail);
                stepForCve99491Output(tail);
            }
            if (!alive) {
                exited = true;
                break;
            }
            Thread.sleep(CVE99491_POLL_MS);
        }
        boolean timedOut = !exited;
        if (timedOut) {
            append(channel + " [超时] direct 引擎超过 " + (CVE99491_RUN_TIMEOUT_MS / 1000L)
                    + " 秒仍未退出，终止并进入失败裁决");
            stopPayload();
        }
        String output = run("cat " + CVE99491_RUN_LOG + " 2>/dev/null", true).output;
        if (output == null) {
            output = "";
        }
        appendCve99491Output(output);
        return new CveRunResult(output, timedOut);
    }

    /** APK 内 assets 顶层文件名集合（资产存在性预检用）。 */
    private Set<String> listAssetNames() {
        Set<String> names = new LinkedHashSet<>();
        try {
            String[] listed = assets.list("");
            if (listed != null) {
                for (String name : listed) {
                    if (name != null && !name.isEmpty()) {
                        names.add(name);
                    }
                }
            }
        } catch (Throwable ignored) {
            // 列不出来按"缺失"处理会在下面变成明确的 fallback 日志；这里先给空集。
        }
        return names;
    }


    /** 99491 部署门：超时按路径可配置，语义沿用 DeployGate（READY 必须显式完成）。 */
    private DeployGate deployAssets(RootPath path, long timeoutMs) throws InterruptedException {
        final DeployGate gate = new DeployGate(timeoutMs);
        Thread deploy = new Thread(() -> {
            try {
                deployer.stageAll(path);
                gate.markCompleted();
            } catch (Throwable error) {
                gate.fail(error);
            }
        }, "lhasa-deploy-" + path.key());
        deploy.start();
        DeployGate.Result result = gate.await(deploy);
        if (result != DeployGate.Result.READY) {
            // 和 98260 相同的收尾顺序：先停写入、确认线程退出，再决定回退/失败。
            deployer.cancel();
            deploy.interrupt();
            try {
                deploy.join(DEPLOY_JOIN_MS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
        return gate;
    }

    /**
     * App 侧 su 验收：`su -c id` 必须是 uid=0 且 ksu 域（`u:r=ksu:s0`）。
     *
     * <p>二进制自己的 `[f] su_check=` 是主证据；这里做二次确认，防止"模块 Live 但 su 没生效"。
     * 只跑一条命令、不带额外引号层（Shizuku sh → su 的嵌套引号容易坏）。
     */
    private boolean verifyCve99491Acceptance() {
        try {
            CommandResult id = run("if [ -x /system/bin/su ]; then /system/bin/su -c id; "
                    + "elif [ -x /data/adb/ksu/bin/su ]; then /data/adb/ksu/bin/su -c id; "
                    + "else echo no-su; fi", false);
            String output = id.output == null ? "" : id.output;
            boolean ok = BootGuard.isKernelSuIdentityOk(output);
            append("[99491] [f] su 验收 uid=0&ksu=" + ok + " → " + oneLine(output));
            return ok;
        } catch (Throwable error) {
            append("[99491] [f] su 验收失败：" + friendly(error));
            return false;
        }
    }

    /** App 侧复核模块是否已在 /proc/modules 里 Live（成功路径用来确认"不用再 late-load"）。 */
    private boolean kernelSuModuleLiveNow() {
        try {
            String modules = run("grep -m1 '^kernelsu ' /proc/modules 2>/dev/null", true).output;
            boolean live = BootGuard.isKernelSuLive(modules);
            append("[99491] [f] /proc/modules kernelsu Live=" + live
                    + (live ? "（模块已加载，跳过 App 侧 late-load）" : ""));
            return live;
        } catch (Throwable error) {
            append("[99491] [f] /proc/modules 复核失败：" + friendly(error));
            return false;
        }
    }

    private void finishCve99491Success(String channel, boolean accepted, boolean moduleLive)
            throws Exception {
        run(BootGuard.clearFailureCommand(), true);
        clearRunMarker();
        run(BootGuard.clearStageCommand(), true);
        state = State.COMPLETE;
        selinuxAfterRoot = enforceNow();
        append(channel + " [f] su_check / MODULE_LOADED 命中：KernelSU 模块已接管");
        append(channel + " 模块已 Live："
                + (moduleLive
                ? "App 复核 /proc/modules 确认，跳过 App 侧 late-load（不重复加载）"
                : "二进制报告已加载（App 复核 /proc/modules 未命中，未重复 late-load）"));
        append(channel + " 临时提权链（direct 引擎 + ko 后端）成功，本次未使用 98260");
        append(channel + " SELinux " + selinuxAfterRoot);
        append(String.format(Locale.US, "[耗时] 99491 链从点击到接管 %.1fs · path=%s",
                (System.currentTimeMillis() - startedAt) / 1000.0, RootPath.WACOM_99491.key()));
        callbacks.onStatus("99491 已完成 · KernelSU 已接管 · SELinux " + selinuxAfterRoot);
        callbacks.onState(State.COMPLETE, accepted
                ? "99491 全部完成 · su 验收通过（uid=0 · u:r=ksu:s0）· SELinux " + selinuxAfterRoot
                : "99491 二进制报告已接管 · App 侧 su 验收未通过（Shizuku 可能断开）· SELinux "
                        + selinuxAfterRoot);
    }

    /** 按裁决落地：回退 98260 / PARKED / dirty boot。 */
    private void settleCve99491Failure(String channel, RootPathDecision.Decision decision, String boot)
            throws Exception {
        switch (decision) {
            case FALLBACK_98260:
                fallbackTo98260(channel + " 零内核写之前失败");
                return;
            case PARKED:
                recordCve99491Failure(BootGuard.Cve99491Failure.PARKED, boot);
                run(BootGuard.clearStageCommand(), true);
                state = State.PARKED;
                append(channel + " 已 PARKED：本 boot 不再写内核，请重启设备后再试 99491");
                callbacks.onState(State.PARKED, "99491 已 PARKED · 请重启设备后再试");
                return;
            case DIRTY_BOOT:
                recordCve99491Failure(BootGuard.Cve99491Failure.WRITE_FAILURE, boot);
                run(BootGuard.clearStageCommand(), true);
                state = State.FAILED;
                append(channel + " 写内核后失败：本次开机已置 dirty（两条链共享），禁止重跑");
                append(channel + " 必须重启设备；重启前不要再点任何提权按钮");
                callbacks.onState(State.FAILED, "99491 写内核后失败 · dirty boot · 必须重启设备");
                return;
            case SUCCESS:
            default:
                // 二进制报告成功但外部复核失败：按已接管处理，避免把成功误报成 dirty。
                finishCve99491Success(channel, false, kernelSuModuleLiveNow());
        }
    }

    /**
     * 记录 99491 失败并绑定 boot_id（归因：上次/本次开机）。
     *
     * <p>优先用预检里读到的 boot_id：失败后 Shizuku 可能已断开，再读一次会拿不到记录，
     * 而 dirty 标记恰恰是"这次开机不能重跑"的唯一凭据。
     */
    private void recordCve99491Failure(BootGuard.Cve99491Failure kind, String bootId) {
        try {
            String boot = bootId == null ? "" : bootId.trim();
            if (boot.isEmpty()) {
                boot = run("cat /proc/sys/kernel/random/boot_id 2>/dev/null", true).output.trim();
            }
            if (boot.isEmpty()) {
                append("[99491] 警告：读不到 boot_id，dirty 记录未写入；请重启设备后再试任何提权链");
                return;
            }
            run(BootGuard.recordCve99491FailureCommand(boot, kind), true);
            append("[99491] 已记录本次失败：" + kind.token + "（boot_id=" + boot + "）");
        } catch (Exception ignored) {
            // 记录失败不能掩盖原始错误；UI 仍会提示必须重启。
        }
    }

    /** 写前失败的自动回退：切回 98260 链继续，内核此时应处于干净状态。 */
    private void fallbackTo98260(String reason) throws Exception {
        append("[99491] " + reason);
        append("[回退] 符合 D4：零内核写之前失败 → 自动回退 98260（定时器链），无需重启");
        callbacks.onStatus("99491 写前失败 · 自动回退 98260");
        activePath = RootPath.TIMER_98260;
        mirroredStage = "";
        payloadLines.clear();
        run(BootGuard.clearStageCommand(), true);
        runRootChain();
    }

    /** 99491 二进制输出统一带 `[99491] ` 通道前缀（§10），并按行去重（轮询会重复读到同一行）。 */
    private void appendCve99491Output(String text) {
        if (text == null || text.trim().isEmpty()) {
            return;
        }
        for (String line : text.split("\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (payloadLines.add(trimmed)) {
                append("[99491] " + trimmed);
            }
        }
    }

    /** 按二进制内部标记推进步骤，让 UI 进度条与日志对齐（direct 引擎阶段）。 */
    private void stepForCve99491Output(String text) {
        if (text == null || text.isEmpty()) {
            return;
        }
        int target = -1;
        for (String raw : text.split("\\n")) {
            String line = raw.trim();
            if (line.startsWith("[p] profile_ok") || line.startsWith("[p] engine=")) {
                target = Math.max(target, 2);
            } else if (line.startsWith("[p] anchor")) {
                target = Math.max(target, 3);
            } else if (line.startsWith("[+] cred") || line.startsWith("[+] fsuid")
                    || line.startsWith("[+] caps")) {
                target = Math.max(target, 4);
            } else if (line.startsWith("[+] setcon") || line.contains("permissive window")) {
                target = Math.max(target, 5);
            } else if (line.startsWith("[ko]") || line.startsWith("[step] direct root")
                    || line.startsWith("MODULE_LOADED") || line.startsWith("[f] module_live")
                    || line.startsWith("[f] su_check") || line.contains("su_check_begin")) {
                target = Math.max(target, 6);
            }
        }
        if (target >= 0 && target != currentStep) {
            step(target);
        }
    }

    private void writeStageQuietly(String stage) {
        try {
            run(BootGuard.markCommand(stage), true);
        } catch (Exception ignored) {
            // 面包屑写失败不该影响主流程。
        }
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

    /**
     * ksud 复用必须按身份判断：大小精确匹配且可执行，才算同一个文件。
     * 之前只看 >1MB，APK 换了新件也可能继续用旧的。
     */
    private void stageKsudIfNeeded() throws Exception {
        CommandResult probe = run("if [ -x " + KSUD_FILE + " ]; then stat -c %s " + KSUD_FILE
                + "; else echo 0; fi", true);
        long remote = -1L;
        try {
            remote = Long.parseLong(probe.output.trim());
        } catch (NumberFormatException ignored) {
            remote = -1L;
        }
        if (remote == KSUD_BYTES) {
            append("[部署] ksud 已存在且大小匹配（" + remote + " 字节），跳过传输");
            return;
        }
        if (remote > 0) {
            append("[部署] ksud 身份不匹配（" + remote + " ≠ " + KSUD_BYTES + " 字节或不可执行），重新投放");
        }
        deployer.stage("ksud");
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
                    mirrorPayloadStage(tail);
                }
                BootGuard.Outcome outcome = BootGuard.classify(tail);
                if (outcome == BootGuard.Outcome.SUCCESS) {
                    append(String.format(Locale.US, "[耗时] payload 成功，总耗时 %.1fs（第 %d 次尝试，累计未命中 %d 次）",
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
                mirrorPayloadStage(tail);
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
            // 99491 的 exp 在专用工作目录里，运行日志在外层；profile/ko/ksud 保留（下次按需校验复用）。
            run("rm -f " + CVE99491_BINARY + " " + CVE99491_RUN_LOG + " 2>/dev/null; true", true);
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
            // 维护任务结束，把状态回到"已完成"，避免界面一直显示"正在诊断"。
            callbacks.onState(state, result.isSuccess() ? "维护完成" : "维护失败 · 详见日志");
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
                + "echo \"MODULES=$(grep -m1 '^kernelsu ' /proc/modules 2>/dev/null)\"; "
                + "echo \"KSUDIR=$(ls -d /sys/module/kernelsu 2>/dev/null)\"; "
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
        String[] labels = stepLabels(activePath);
        String label = value >= 0 && value < labels.length ? labels[value] : "全部完成";
        lastStepLabel = label;
        callbacks.onStep(value, label);
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
