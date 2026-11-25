package com.gkeyes.lhasa26.core;

/**
 * 99491 链失败后的处置裁决（docs/99491-test-plan.md §3 D4）：
 *
 * <ul>
 *   <li><b>零内核写之前</b>失败 → 允许自动回退 98260（定时器链）。98260 本来就在另一条链上，
 *       此时内核状态没被动过，回退不会放大风险。</li>
 *   <li><b>写内核之后</b>失败 → 置 dirty boot，要求重启。写后失败（cred swap / SELinux 窗口 /
 *       模块加载）意味着内核里已经有半截状态，再跑任何一条链都是二次写。</li>
 *   <li>PARKED（本 boot 不再写）→ 不再继续；写前 PARKED 不 dirty（但也不回退，因为 PARKED 的
 *       语义就是本 boot 不该再碰内核），写后 PARKED 一样按 dirty 处理。</li>
 * </ul>
 *
 * <p>证据来自二进制自己打出的标记（§10 契约）：{@code [p] profile_ok}、{@code [p] anchor slide=}
 * 属于写前；{@code [+] swap uid=0}、{@code [+] cred == real_cred}、{@code [+] setcon}、
 * {@code MODULE_LOADED}、{@code [f] module_live=1}、{@code [f] su_check=} 属于写后。
 * 没有任何可归因证据时按 fail-closed 处理：宁可要求重启，也不能假设"它没写"。
 *
 * <p>纯逻辑，可在 JVM 单测里直接覆盖。
 */
public final class RootPathDecision {

    public enum Decision {
        /** 二进制报告已接管（su_check 命中）。 */
        SUCCESS,
        /** 明确证明零内核写之前失败 → 自动回退 98260。 */
        FALLBACK_98260,
        /** PARKED：本次开机不再写内核，要求重启后再跑 99491。 */
        PARKED,
        /** 已发生内核写（或无法归因）→ dirty boot，必须重启。 */
        DIRTY_BOOT
    }

    private RootPathDecision() {
    }

    /**
     * 按二进制日志裁决失败处置。
     *
     * @param tail 99491 二进制的完整输出（可空）
     */
    public static Decision decide(String tail) {
        return decide(tail, 0);
    }

    /**
     * 带退出码的裁决。退出码只在"没有任何标记"时提供额外信号：
     * timeout(124) 视为无法归因 → dirty；非零退出且无写前证据 → dirty（fail-closed）。
     */
    public static Decision decide(String tail, int exitCode) {
        String output = tail == null ? "" : tail;
        BootGuard.Cve99491Outcome outcome = BootGuard.classifyCve99491(output);
        if (outcome == BootGuard.Cve99491Outcome.SUCCESS) {
            return Decision.SUCCESS;
        }
        boolean kernelWrite = BootGuard.hasCve99491KernelWrite(output);
        boolean parked = outcome == BootGuard.Cve99491Outcome.PARKED;
        boolean aborted = outcome == BootGuard.Cve99491Outcome.ABORT_BOOT
                || exitCode == BootGuard.TIMEOUT_EXIT;
        if (parked) {
            return kernelWrite ? Decision.DIRTY_BOOT : Decision.PARKED;
        }
        if (aborted) {
            // 中止（panic / holding zombie / timeout）一律按内核已被动过处理：这里没有"干净中止"。
            return Decision.DIRTY_BOOT;
        }
        if (kernelWrite) {
            return Decision.DIRTY_BOOT;
        }
        // 写前标记：profile/anchor 阶段确实跑过，但还没到第一次写。
        if (hasPreWriteEvidence(output)) {
            return Decision.FALLBACK_98260;
        }
        // 一点证据都没有：不能证明"零写"，fail-closed。
        return Decision.DIRTY_BOOT;
    }

    /** 输出里是否出现过写前标记（此时失败可安全回退 98260）。 */
    public static boolean hasPreWriteEvidence(String tail) {
        if (tail == null || tail.isEmpty()) {
            return false;
        }
        for (String raw : tail.split("\\n")) {
            String line = raw.trim();
            if (line.startsWith("[p] ")) {
                return true;
            }
            if (line.contains("PROFILE_MISMATCH") || line.contains("[p]")) {
                return true;
            }
        }
        return false;
    }

    /** 裁决的人话说明，写进会话日志。 */
    public static String describe(Decision decision) {
        if (decision == null) {
            return "未知裁决";
        }
        switch (decision) {
            case SUCCESS:
                return "二进制报告已接管（su_check 命中）";
            case FALLBACK_98260:
                return "零内核写之前失败 → 允许自动回退 98260";
            case PARKED:
                return "PARKED：本次开机不再写内核，请重启后再试 99491";
            case DIRTY_BOOT:
            default:
                return "已发生内核写或无法归因 → dirty boot，必须重启设备";
        }
    }
}
