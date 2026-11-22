package com.gkeyes.lhasa26.core;

/**
 * Boot-scoped retry policy for the lhasa26 temporary-root workflow.
 *
 * Failures are structurally different and the difference decides whether the same boot may be
 * retried at all:
 *
 *  - a clean leak failure, where nothing was planted;
 *  - a planted-node failure ("holding zombie"), where the timerqueue node stays linked in the live
 *    task's posix_cputimers rbtree. Running again makes release_task() erase the same freed node a
 *    second time and faults the kernel. Blocked for the rest of the boot, whatever SELinux says;
 *  - a SELinux-only failure, where the first phase landed but the cred phase did not.
 */
public final class BootGuard {

    /** Result of inspecting one line of payload output. */
    public enum Outcome {
        SUCCESS,
        RETRY_SAFE,
        ABORT_BOOT,
        CONTINUE
    }

    /** What the recorded failure of this boot allows. */
    public enum Retry {
        ALLOWED,
        PERMISSIVE_RETRY,
        BLOCKED
    }

    /**
     * Written by the launch wrapper as `&lt;pgid&gt;:&lt;boot_id&gt;`.
     *
     * The boot id is essential: /data/local/tmp survives reboots, and a stale pgid can be reused by
     * an unrelated shell-uid process. A payload that already elevated itself runs as uid=0, which a
     * uid=2000 shell cannot signal — EPERM therefore means "still alive", not "gone".
     */
    public static final String PID_FILE = "/data/local/tmp/.lhasa_pid";

    /** 阶段面包屑：每个会碰内核的动作开跑前写一次，成功后清空。 */
    public static final String STAGE_FILE = "/data/local/tmp/.lhasa_stage";

    /** 本次开机的失败记录：`<boot_id> <abort|permissive|enforcing>`。 */
    public static final String FAILED_FILE = "/data/local/tmp/.lhasa_failed_boot";

    /** timeout(1) 被触发时的退出码。 */
    public static final int TIMEOUT_EXIT = 124;

    private static final char BOOT_SEP = ':';
    private static final String BOOT_ID_READ = "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)";

    private static final String[] ABORT_MARKERS = {
            "holding zombie",
            "Kernel panic",
            "kernel panic",
            "BUG: unable to handle",
            "Internal error"
    };

    private static final String[] SUCCESS_MARKERS = {
            "[child-cred] uid=0",
            "[cred] rooted"
    };

    /**
     * Failures that leave nothing planted.
     *
     * Deliberately does NOT contain "[selinux] attempt ": that line appears while the chain is still
     * progressing normally (attempt 1/6 happens right at the start).
     */
    private static final String[] RETRY_MARKERS = {
            "leak failed",
            "unsupported kernel",
            "slide_probe failed"
    };

    private BootGuard() {
    }

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

    public static boolean isSupportedKernel(String kernel) {
        return KernelSupport.isSupported(kernel);
    }

    public static String kernelWarning(String kernel) {
        return "（警告）内核不在已验证 profile 表：" + kernel
                + " · 将按现有 offsets 继续尝试；若失败或内核异常，请重启后再试，不要在本次开机重复点击";
    }

    /** 单次探测命令加硬超时；`-k 2` 是第二道保险：SIGTERM 后 2 秒仍不退就 SIGKILL。 */
    public static String withTimeout(int seconds, String command) {
        return "timeout -k 2 " + seconds + " " + command;
    }

    public static String markCommand(String stage) {
        return "echo '" + sanitize(stage) + " " + System.currentTimeMillis() + "' > " + STAGE_FILE;
    }

    public static String clearStageCommand() {
        return "rm -f " + STAGE_FILE;
    }

    public static String recordFailureCommand(String bootId, boolean abort, boolean permissive) {
        if (bootId == null || bootId.isEmpty()) {
            return "true";
        }
        String kind = abort ? "abort" : (permissive ? "permissive" : "enforcing");
        return "echo '" + sanitize(bootId) + " " + kind + "' > " + FAILED_FILE;
    }

    public static String clearFailureCommand() {
        return "rm -f " + FAILED_FILE;
    }

    /** 解析失败记录；兼容旧格式 `<boot_id> 0|1`。 */
    public static Retry parseFailure(String content, String currentBootId) {
        if (content == null || content.trim().isEmpty()) {
            return Retry.ALLOWED;
        }
        String[] parts = content.trim().split("\\s+");
        if (parts.length < 2) {
            return Retry.BLOCKED;
        }
        if (currentBootId != null && !currentBootId.isEmpty() && !currentBootId.equals(parts[0])) {
            return Retry.ALLOWED;
        }
        String kind = parts[1];
        if ("abort".equals(kind)) {
            return Retry.BLOCKED;
        }
        if ("permissive".equals(kind) || "0".equals(kind)) {
            return Retry.PERMISSIVE_RETRY;
        }
        return Retry.BLOCKED;
    }

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

    private static String sanitize(String value) {
        if (value == null) {
            return "unknown";
        }
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    /** Launches the payload in its own session and records `&lt;pgid&gt;:&lt;boot_id&gt;`. */
    public static String launchCommand(String binary, String arguments, String logPath) {
        return "toybox setsid sh -c '" + binary + " " + arguments
                + " > " + logPath + " 2>&1 < /dev/null & echo \"$$" + BOOT_SEP + "\""
                + BOOT_ID_READ + " > " + PID_FILE
                + "' >/dev/null 2>&1 &";
    }

    /**
     * Signals the recorded process group, but only when the record belongs to the running boot.
     *
     * A payload that already elevated itself cannot be signalled by this uid=2000 shell; the call is
     * best-effort and must not be treated as "nothing running".
     */
    public static String killCommand() {
        return "if [ -s " + PID_FILE + " ]; then "
                + "rec=$(cat " + PID_FILE + " 2>/dev/null); "
                + "p=${rec%%" + BOOT_SEP + "*}; b=${rec##*" + BOOT_SEP + "}; "
                + "now=" + BOOT_ID_READ + "; "
                + "if [ -n \"$now\" ] && [ \"$b\" = \"$now\" ]; then "
                + "kill -TERM -$p 2>/dev/null; sleep 1; kill -KILL -$p 2>/dev/null; "
                + "fi; rm -f " + PID_FILE + "; fi; true";
    }

    /**
     * Prints 1 when the recorded process group still exists in this boot, 0 otherwise.
     *
     * `kill -0` fails with EPERM for a live process owned by another uid (which is exactly what an
     * elevated payload looks like), and with ESRCH when it is really gone. Treating every failure as
     * "alive" made the early-exit check useless, so the two cases are separated here.
     */
    public static String aliveCommand() {
        return "if [ -s " + PID_FILE + " ]; then "
                + "rec=$(cat " + PID_FILE + " 2>/dev/null); "
                + "p=${rec%%" + BOOT_SEP + "*}; b=${rec##*" + BOOT_SEP + "}; "
                + "now=" + BOOT_ID_READ + "; "
                + "if [ -n \"$now\" ] && [ ! \"$b\" = \"$now\" ]; then rm -f " + PID_FILE + "; echo 0; "
                + "elif [ -z \"$p\" ]; then rm -f " + PID_FILE + "; echo 0; "
                + "elif kill -0 -$p 2>/dev/null; then echo 1; "
                + "else "
                + "  msg=$(kill -0 -$p 2>&1); "
                + "  case \"$msg\" in "
                + "    *ermitted*) echo 1 ;; "
                + "    *) rm -f " + PID_FILE + "; echo 0 ;; "
                + "  esac; "
                + "fi; "
                + "else echo 0; fi";
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
