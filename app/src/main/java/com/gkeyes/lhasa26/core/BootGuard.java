package com.gkeyes.lhasa26.core;

/**
 * Boot-scoped retry policy for the lhasa26 temporary-root workflow.
 *
 * The payload can fail in two structurally different ways and the difference decides whether the
 * same boot may be retried at all:
 *
 *  - a leak-stage failure, where nothing was planted and the heap is still clean, so restarting the
 *    payload immediately is safe;
 *  - a planted-node failure ("holding zombie"), where the timerqueue node stays linked in the live
 *    task's posix_cputimers rbtree. Running the payload again makes release_task() erase the same
 *    freed node a second time, which faults the kernel instead of returning an error.
 *
 * Treating both as "retry" is why a failed boot can end in a panic. Everything here is pure logic
 * plus the exact shell strings the workflow needs, so it can be exercised without a device.
 *
 * A kernel that has no profile line is <b>not</b> blocked: the run continues with a warning, because
 * a mismatched build sometimes still lands and the user may prefer one attempt over none.
 */
public final class BootGuard {

    /** Result of inspecting one line of payload output. */
    public enum Outcome {
        SUCCESS,
        RETRY_SAFE,
        ABORT_BOOT,
        CONTINUE
    }

    /**
     * Written by the launch wrapper. Under setsid the recorded shell id doubles as the process group
     * id, which is what makes a whole-tree kill possible without scanning /proc.
     */
    public static final String PID_FILE = "/data/local/tmp/.lhasa_pid";

    /**
     * 阶段面包屑：每个会碰内核的动作开跑前写一次，成功后清空。
     * 下次启动时若这行还在，就说明上一次运行停在了那个阶段——重启之后再也不用猜是谁弄的。
     */
    public static final String STAGE_FILE = "/data/local/tmp/.lhasa_stage";

    /** timeout(1) 被触发时的退出码，用来把"卡死"和"程序自己返回失败"区分开。 */
    public static final int TIMEOUT_EXIT = 124;

    /**
     * Payload prefixes that mean the kernel heap is already dirty. Checked before the success markers
     * because a tail containing both still left a dangling node behind.
     */
    private static final String[] ABORT_MARKERS = {
            "holding zombie",
            "Kernel panic",
            "kernel panic",
            "BUG: unable to handle",
            "Internal error"
    };

    /**
     * Markers that are only emitted once the cred stage actually landed. Deliberately excludes
     * "holding pages" and "[selinux] already permissive": the first is an intermediate plant state,
     * the second only says the SELinux phase is done while uid is still 2000.
     */
    private static final String[] SUCCESS_MARKERS = {
            "[child-cred] uid=0",
            "[cred] rooted"
    };

    /** Failures that leave nothing planted, so the same boot can run the payload again. */
    private static final String[] RETRY_MARKERS = {
            "leak failed",
            "[selinux] attempt "
    };

    private BootGuard() {
    }

    /**
     * Classifies a payload log tail.
     *
     * Abort markers win over success markers on purpose: a tail that reports a planted node and later
     * a success line still leaves the dangling node queued, and the next run must not reuse it.
     */
    public static Outcome classify(String tail) {
        if (tail == null || tail.isEmpty()) {
            return Outcome.CONTINUE;
        }
        if (containsAny(tail, ABORT_MARKERS)) {
            return Outcome.ABORT_BOOT;
        }
        if (containsAny(tail, SUCCESS_MARKERS)) {
            return Outcome.SUCCESS;
        }
        if (containsAny(tail, RETRY_MARKERS)) {
            return Outcome.RETRY_SAFE;
        }
        return Outcome.CONTINUE;
    }

    /** True when the running kernel string has a line in lhasa_profile.txt. */
    public static boolean isSupportedKernel(String kernel) {
        return KernelSupport.isSupported(kernel);
    }

    /**
     * Warning shown when the kernel has no profile line. The run still proceeds: offsets from another
     * build only sometimes fault, and an explicit attempt is often worth more than a refusal.
     */
    public static String kernelWarning(String kernel) {
        return "（警告）内核不在已验证 profile 表：" + kernel
                + " · 将按现有 offsets 继续尝试；若失败或内核异常，请重启后再试，不要在本次开机重复点击";
    }

    /**
     * 给单次探测命令套上硬超时。
     *
     * 采样器（perf_slide）和 tracefs 探测在异常内核上可能永远不返回；没有 timeout 时它们会
     * 以 root 身份常驻，把设备拖进 soft lockup，最后表现成"用一次就重启一次"。
     * timeout 是 toybox 自带，Android 9 以后都在。
     */
    public static String withTimeout(int seconds, String command) {
        return "timeout " + seconds + " " + command;
    }

    /** 记下"接下来要碰内核了"；失败或重启后靠它定位。 */
    public static String markCommand(String stage) {
        return "echo '" + sanitize(stage) + " " + System.currentTimeMillis() + "' > " + STAGE_FILE;
    }

    /** 成功走完后清掉面包屑。 */
    public static String clearStageCommand() {
        return "rm -f " + STAGE_FILE;
    }

    /**
     * 把上一次残留的阶段读成一句人话；没有残留就返回空串。
     * timestamp 用于判断是不是本次开机的事。
     */
    public static String leftoverStageHint(String stageFileContent) {
        if (stageFileContent == null || stageFileContent.trim().isEmpty()) {
            return "";
        }
        String[] parts = stageFileContent.trim().split("\\s+");
        String stage = parts[0];
        String label;
        switch (stage) {
            case "payload":
                label = "主利用（uaf_plant_replay）";
                break;
            case "ksu":
                label = "KernelSU late-load（加载内核模块）";
                break;
            case "probe-perf":
                label = "perf_slide 采样";
                break;
            case "probe-slide":
                label = "slide_probe 测量";
                break;
            case "diagnose":
                label = "reach_probe 诊断";
                break;
            default:
                label = stage;
                break;
        }
        return "上次运行停在「" + label + "」阶段，没有正常结束——如果是重启造成的，那就是这个阶段把设备带走的。";
    }

    private static String sanitize(String stage) {
        if (stage == null) {
            return "unknown";
        }
        return stage.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    /**
     * Starts the payload in its own session so the whole group can be signalled later, and records the
     * shell id (the group id under setsid) to {@link #PID_FILE}.
     */
    public static String launchCommand(String binary, String arguments, String logPath) {
        return "toybox setsid sh -c '" + binary + " " + arguments
                + " > " + logPath + " 2>&1 < /dev/null & echo $$ > " + PID_FILE
                + "' >/dev/null 2>&1 &";
    }

    /**
     * Signals the recorded process group.
     *
     * pkill and killall cannot be used here: /proc is mounted hidepid=invisible on this device, so an
     * unprivileged scan never sees the payload and the old process keeps running next to the new one.
     */
    public static String killCommand() {
        return "if [ -s " + PID_FILE + " ]; then p=$(cat " + PID_FILE + "); "
                + "kill -TERM -$p 2>/dev/null; sleep 1; kill -KILL -$p 2>/dev/null; "
                + "rm -f " + PID_FILE + "; fi; true";
    }

    /** Prints 1 when the recorded process group still exists, 0 otherwise. */
    public static String aliveCommand() {
        return "if [ -s " + PID_FILE + " ]; then p=$(cat " + PID_FILE + "); "
                + "kill -0 -$p 2>/dev/null && echo 1 || echo 0; else echo 0; fi";
    }

    private static boolean containsAny(String haystack, String[] needles) {
        for (String needle : needles) {
            if (haystack.contains(needle)) {
                return true;
            }
        }
        return false;
    }
}
