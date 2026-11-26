package com.gkeyes.lhasa26.core;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 99491 链在"内核模块已加载成功"之后的 KernelSU userspace 收尾。
 *
 * <p>背景（真机 ROOT12）：ko 后端把 kernelsu.ko finit_module 进内核后，模块是 Live、
 * {@code /system/bin/su} 也可用且 uid=0，但 SELinux context 仍是 {@code kernel}——
 * KSU 的 sepolicy/features（sucompat 的 ksu 域迁移）由 ksud late-load 的 **userspace 阶段**
 * 完成。98260 之所以 context 正常，是因为它本来就跑 ksud 全流程。所以模块 Live 后需要补一步
 * （no-permissive 路径下还要先经 su 安装 ksud，见 {@link #FINISH_COMMAND}）。
 *
 * <p>验收规则（Lead 2026-11-26 确认，先宽后紧）：
 * <ul>
 *   <li>uid=0 且 context 含 {@code u:r=ksu:s0} → 成功（正常）；</li>
 *   <li>uid=0 且 context 为 {@code kernel}（或其它非 shell/untrusted 域）→ 也成功，
 *       但标注"context=&lt;实际值&gt;（ksud 收尾后降级）"；</li>
 *   <li>uid≠0，或 uid=0 却落在 shell/untrusted 域 → 失败（fail-closed）。</li>
 * </ul>
 *
 * <p>本类只在"模块已 Live"时被调用；绝不用于 exp 失败/写前阶段。收尾命令失败不回滚已加载的
 * 模块，最终以 su 验收为准（失败只在日志里留 note）。
 *
 * <p>执行命令通过 {@link Runner} 注入，JVM 单测不跑真实进程。
 */
public final class KsuUserspaceFinisher {

    /** KSU sucompat 期望的 userspace 入口（设备侧最终位置）。 */
    public static final String KSUD_BIN = "/data/adb/ksud";
    /** App 已按需投放的 ksud 源文件；exp 是否已装好不可假设，这里兜底幂等安装。 */
    public static final String KSUD_SRC = "/data/local/tmp/ksud";
    /** KernelSU 模块 KMI；App 侧必须显式传，不能依赖设备推导。 */
    public static final String KMI = "android17-6.18";

    /**
     * 收尾命令（Lead 指定，合并成一条 su 调用）：
     *
     * <pre>su -c '[ -x /data/adb/ksud ] || cp /data/local/tmp/ksud /data/adb/ksud;
     * chmod 755 /data/adb/ksud 2>/dev/null;
     * /data/adb/ksud late-load --allow-shell --kmi android17-6.18'</pre>
     *
     * <p>为什么先装 ksud：exp 的 ko 后端在 permissive 窗口内会把 ksud 复制到 /data/adb/ksud，
     * 但该步骤是否成功不可假设（历史 no-permissive 实验里就写不了），所以这里用
     * `[ -x ] || cp` 幂等兜底；已存在时跳过，不会覆盖。
     */
    public static final String FINISH_COMMAND =
            "su -c '[ -x " + KSUD_BIN + " ] || cp " + KSUD_SRC + " " + KSUD_BIN
                    + "; chmod 755 " + KSUD_BIN + " 2>/dev/null; "
                    + KSUD_BIN + " late-load --allow-shell --kmi " + KMI + "'";

    /** 收尾后的等待预算：真机 KernelSU sepolicy 初始化通常 <2s，给 10s 轮询。 */
    public static final long DEFAULT_WAIT_MS = 10000L;
    public static final long DEFAULT_POLL_MS = 2000L;

    public static final String KSU_DOMAIN = "ksu";
    private static final String[] UNSAFE_PREFIXES = {"shell", "untrusted"};

    private static final Pattern UID = Pattern.compile("\\buid=(\\d+)");
    private static final Pattern COLON_CONTEXT = Pattern.compile("u:r:([A-Za-z0-9_]+):s0");
    private static final Pattern EQUALS_CONTEXT = Pattern.compile("u:r=([A-Za-z0-9_]+):s0");
    private static final Pattern CONTEXT_KV = Pattern.compile("context=([A-Za-z0-9_:]+)");

    private KsuUserspaceFinisher() {
    }

    /** 设备侧命令执行抽象：单测注入假实现，生产用 Shizuku 的 run()。 */
    public interface Runner {
        /** `su -c 'id; getenforce'` 的输出（uid/context/enforce 都在里面）。 */
        String runSuId() throws Exception;

        /** 执行一次 {@link #FINISH_COMMAND}。 */
        String runFinish() throws Exception;

        /** 轮询间隔让出 CPU；测试里可以空实现。 */
        void sleepMs(long millis) throws InterruptedException;
    }

    public enum Result {
        /** 模块未 Live：不执行收尾（调用方不应走到这里）。 */
        SKIPPED_NOT_LIVE,
        /** 收尾前 su 已在 u:r=ksu:s0：无需执行命令。 */
        ALREADY_KSU,
        /** 收尾后 su 进入 u:r=ksu:s0（正常成功）。 */
        FINISHED_KSU,
        /** 收尾后 uid=0 但 context 不是 ksu（如 kernel）：降级成功并标注。 */
        FINISHED_DEGRADED,
        /** uid≠0 或 context=shell/untrusted：fail-closed。 */
        FAILED
    }

    /** 一次收尾的完整结论；字段直接进日志/状态文案。 */
    public static final class Verdict {
        public final Result result;
        /** 是否允许把本次 99491 运行判为成功。 */
        public final boolean success;
        /** 成功但 context 不是 ksu（"ksud 收尾后降级"）。 */
        public final boolean degraded;
        /** 最终观测到的 context 域（ksu/kernel/空=未知）。 */
        public final String contextDomain;
        /** 最终 `su -c id` 输出（已单行化）。 */
        public final String suIdLine;
        /** 最终 `getenforce` 值（可空）。 */
        public final String enforce;
        /** 给用户看的一句话结论。 */
        public final String detail;
        /** 是否执行过收尾命令（模块未 Live 时为 false）。 */
        public final boolean finishAttempted;
        /** 收尾命令失败信息；成功为空串。 */
        public final String finishError;
        /** 状态里展示的 context 说明（如 `context=kernel（ksud 收尾后降级）`）。 */
        public final String contextNote;

        Verdict(Result result, boolean success, boolean degraded, String contextDomain,
                String suIdLine, String enforce, String detail,
                boolean finishAttempted, String finishError, String contextNote) {
            this.result = result;
            this.success = success;
            this.degraded = degraded;
            this.contextDomain = contextDomain == null ? "" : contextDomain;
            this.suIdLine = suIdLine == null ? "" : suIdLine;
            this.enforce = enforce == null ? "" : enforce;
            this.detail = detail == null ? "" : detail;
            this.finishAttempted = finishAttempted;
            this.finishError = finishError == null ? "" : finishError;
            this.contextNote = contextNote == null ? "" : contextNote;
        }
    }

    /** 收尾命令文本（单测/日志用）。 */
    public static String finishCommand() {
        return FINISH_COMMAND;
    }

    /**
     * 模块 Live 后检查 su context，必要时执行一次 ksud userspace 收尾并复验。
     *
     * @param moduleLive 调用方已确认模块 Live（false 时直接 SKIPPED_NOT_LIVE，不碰设备）
     */
    public static Verdict finishIfNeeded(boolean moduleLive, Runner runner) {
        if (!moduleLive) {
            return new Verdict(Result.SKIPPED_NOT_LIVE, false, false, "", "", "",
                    "模块未 Live，跳过 ksud userspace 收尾", false, "", "");
        }
        if (runner == null) {
            throw new IllegalArgumentException("runner == null");
        }
        SuSnapshot current = readSu(runner);
        if (current.uid == 0L && isKsuDomain(current.domain)) {
            return verdict(Result.ALREADY_KSU, true, false, current,
                    "su 已在 u:r=ksu:s0，无需 ksud 收尾", false, "");
        }
        String finishError = "";
        boolean finishAttempted = false;
        try {
            finishAttempted = true;
            runner.runFinish();
        } catch (Throwable error) {
            finishError = describe(error);
        }
        // 轮询等待 KernelSU 完成 sepolicy/features 初始化；预算 10s。
        long waited = 0L;
        SuSnapshot latest = current;
        while (waited < DEFAULT_WAIT_MS) {
            long step = Math.min(DEFAULT_POLL_MS, DEFAULT_WAIT_MS - waited);
            try {
                runner.sleepMs(step);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                break;
            }
            waited += step;
            latest = readSu(runner);
            if (latest.uid == 0L && isKsuDomain(latest.domain)) {
                return verdict(Result.FINISHED_KSU, true, false, latest,
                        "ksud 收尾后 su 进入 u:r=ksu:s0", true, finishError);
            }
        }
        // 10s 后最终复验（与轮询分开，保证"再执行一次 su -c 'id; getenforce'"）。
        SuSnapshot finalSnap = readSu(runner);
        if (finalSnap.uid == 0L) {
            if (isUnsafeDomain(finalSnap.domain)) {
                return verdict(Result.FAILED, false, false, finalSnap,
                        "uid=0 但 context=" + display(finalSnap.domain)
                                + " 属于 shell/untrusted，按 fail-closed 处理",
                        finishAttempted, finishError);
            }
            return verdict(Result.FINISHED_DEGRADED, true, true, finalSnap,
                    "uid=0 · context=" + display(finalSnap.domain)
                            + "（ksud 收尾后降级放行）", finishAttempted, finishError);
        }
        String uidText = finalSnap.uid < 0L ? "未知" : String.valueOf(finalSnap.uid);
        return verdict(Result.FAILED, false, false, finalSnap,
                "最终 su 验收 uid=" + uidText + "（期望 uid=0）", finishAttempted, finishError);
    }

    /** 从 `su -c id` 输出解析 uid；找不到返回 -1。 */
    public static long parseUid(String suOutput) {
        if (suOutput == null) {
            return -1L;
        }
        Matcher matcher = UID.matcher(suOutput);
        if (!matcher.find()) {
            return -1L;
        }
        try {
            return Long.parseLong(matcher.group(1));
        } catch (NumberFormatException ignored) {
            return -1L;
        }
    }

    /**
     * 解析 SELinux context 域。
     *
     * <p>同时接受真机实际的 `u:r:kernel:s0`、契约里的 `u:r=ksu:s0`、以及 `context=kernel`
     * 这种短写；解析不出来返回空串（未知）。
     */
    public static String parseContextDomain(String suOutput) {
        if (suOutput == null || suOutput.isEmpty()) {
            return "";
        }
        Matcher colon = COLON_CONTEXT.matcher(suOutput);
        if (colon.find()) {
            return normalizeDomain(colon.group(1));
        }
        Matcher equals = EQUALS_CONTEXT.matcher(suOutput);
        if (equals.find()) {
            return normalizeDomain(equals.group(1));
        }
        Matcher kv = CONTEXT_KV.matcher(suOutput);
        if (kv.find()) {
            String token = kv.group(1);
            int lastColon = token.lastIndexOf(':');
            String domain = lastColon >= 0 ? token.substring(lastColon + 1) : token;
            return normalizeDomain(domain);
        }
        return "";
    }

    public static boolean isKsuDomain(String domain) {
        return domain != null && KSU_DOMAIN.equalsIgnoreCase(domain.trim());
    }

    /** shell / untrusted 域不能算"uid=0 已提权"。 */
    public static boolean isUnsafeDomain(String domain) {
        if (domain == null) {
            return false;
        }
        String value = domain.trim().toLowerCase(Locale.US);
        for (String prefix : UNSAFE_PREFIXES) {
            if (value.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static String normalizeDomain(String domain) {
        return domain == null ? "" : domain.trim().toLowerCase(Locale.US);
    }

    /** 状态/日志展示：ksu 用契约写法，其它用 `<域>`，未知写"未知"。 */
    static String display(String domain) {
        if (domain == null || domain.isEmpty()) {
            return "未知";
        }
        if (isKsuDomain(domain)) {
            return "u:r=ksu:s0";
        }
        return domain;
    }

    private static Verdict verdict(Result result, boolean success, boolean degraded,
                                   SuSnapshot snapshot, String detail,
                                   boolean finishAttempted, String finishError) {
        String note;
        if (isKsuDomain(snapshot.domain)) {
            note = "context=u:r=ksu:s0";
        } else if (snapshot.domain.isEmpty()) {
            note = "context=未知";
        } else {
            note = "context=" + snapshot.domain;
        }
        if (degraded) {
            note = "context=" + display(snapshot.domain) + "（ksud 收尾后降级）";
        }
        return new Verdict(result, success, degraded, snapshot.domain, snapshot.idLine,
                snapshot.enforce, detail, finishAttempted, finishError, note);
    }

    private static SuSnapshot readSu(Runner runner) {
        String raw;
        try {
            raw = runner.runSuId();
        } catch (Throwable error) {
            raw = "读取失败：" + describe(error);
        }
        return snapshot(raw);
    }

    private static SuSnapshot snapshot(String raw) {
        String output = raw == null ? "" : raw;
        return new SuSnapshot(parseUid(output), parseContextDomain(output),
                oneLine(output), parseEnforce(output));
    }

    private static String parseEnforce(String output) {
        if (output == null) {
            return "";
        }
        if (output.contains("Enforcing")) {
            return "Enforcing";
        }
        if (output.contains("Permissive")) {
            return "Permissive";
        }
        return "";
    }

    private static String oneLine(String value) {
        if (value == null) {
            return "";
        }
        return value.replace('\n', ' ').replace('\r', ' ').trim();
    }

    private static String describe(Throwable error) {
        if (error == null) {
            return "";
        }
        String message = error.getMessage();
        return message == null || message.trim().isEmpty() ? error.toString() : message;
    }

    private static final class SuSnapshot {
        final long uid;
        final String domain;
        final String idLine;
        final String enforce;

        SuSnapshot(long uid, String domain, String idLine, String enforce) {
            this.uid = uid;
            this.domain = domain;
            this.idLine = idLine;
            this.enforce = enforce;
        }
    }
}
