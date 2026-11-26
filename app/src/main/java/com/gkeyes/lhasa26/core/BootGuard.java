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

    public enum Outcome {
        SUCCESS,
        RETRY_SAFE,
        ABORT_BOOT,
        CONTINUE
    }

    public enum Retry {
        ALLOWED,
        PERMISSIVE_RETRY,
        BLOCKED
    }

    /**
     * CVE-2026-99491（real_cred 链）的标记分类。
     *
     * <p>和 98260 的 {@link #classify(String)} 完全分开：99491 的标记契约见
     * docs/99491-test-plan.md §10（{@code [p] profile_ok}、{@code [p] anchor slide=}、
     * {@code [+] swap uid=0}、{@code [+] cred == real_cred}、{@code [+] setcon}、
     * {@code [f] module_live=1 enforce=1}、{@code [f] su_check=uid=0 … u:r=ksu:s0}、
     * {@code PARKED}、{@code MODULE_LOADED}）。98260 的标记数组一个都不动。
     */
    public enum Cve99491Outcome {
        /** 还没看到可归因的 99491 标记。 */
        NONE,
        /** 最终 su 校验命中 ksu 域：整条链接管。 */
        SUCCESS,
        /** 写前失败 / 可安全重试。 */
        RETRY_SAFE,
        /** 二进制报告 PARKED：本 boot 不再写内核。 */
        PARKED,
        /** 中止：panic / holding zombie / 明确 abort。 */
        ABORT_BOOT
    }

    /** 99491 写后失败的归因种类；token 会写进 {@link #FAILED_FILE}，两条链共享 dirty 判定。 */
    public enum Cve99491Failure {
        /** 写内核之后失败：dirty boot。 */
        WRITE_FAILURE("dirty99491"),
        /** PARKED：本次开机不再写内核。 */
        PARKED("parked99491"),
        /** payload 报告节点挂树等不可重跑的中止。 */
        ABORT("abort");

        public final String token;

        Cve99491Failure(String token) {
            this.token = token;
        }
    }

    /** 99491 写阶段标记：出现任意一个就说明内核已被写过（不再允许回退 98260）。 */
    private static final String[] CVE99491_WRITE_MARKERS = {
            "[+] swap",
            "[+] cred",
            "[+] setcon",
            "[+] fsuid",
            "[+] caps bit16",
            "[f] module_live",
            "[f] su_check",
            "MODULE_LOADED",
            "[ko]",
            "[step] direct root",
            "[!] permissive window"
    };

    /** 99491 写前失败标记：安全重试/回退。 */
    private static final String[] CVE99491_RETRY_MARKERS = {
            "leak failed",
            "anchor failed",
            "oracle miss",
            "[p] retry",
            "[p] failed",
            "[p] precheck failed",
            "PROFILE_MISMATCH"
    };

    /** 99491 中止标记：和 98260 共用的 panic/挂树，再加 99491 专属的 abort 行。 */
    private static final String[] CVE99491_ABORT_MARKERS = {
            "holding zombie",
            "Kernel panic",
            "kernel panic",
            "BUG: unable to handle",
            "Internal error",
            "ABORT_BOOT",
            "[!] abort",
            "[p] abort"
    };

    private static final String CVE99491_SU_CHECK_PREFIX = "[f] su_check=";
    private static final String CVE99491_MODULE_LIVE = "[f] module_live=1";
    private static final String CVE99491_KSU_CONTEXT = "u:r=ksu:s0";
    private static final String CVE99491_KSU_CONTEXT_ALT = "u:r:ksu:s0";
    private static final String CVE99491_PARKED = "PARKED";
    private static final String CVE99491_MODULE_LOADED = "MODULE_LOADED";
    /**
     * direct 引擎在 --stage=root 开头就会打印
     * `[!] direct engine: PARKED marker set for this boot; reboot before the next fire run`
     * —— 这是"本 boot 已 fire"的信息行，不应当成失败 tail 里的 PARKED 令牌。
     */
    private static final String CVE99491_PARKED_INFO = "PARKED marker set";
    /** 99491 要求从干净开机开始：Enforcing 且 /proc/modules 里没有 kernelsu。 */
    public static final String KSU_MODULE_NAME = "kernelsu";
    private static final String KSU_LIVE_TOKEN = "Live";

    /**
     * Written by the launch wrapper as `&lt;pgid&gt;:&lt;boot_id&gt;`.
     *
     * The boot id is essential: /data/local/tmp survives reboots, and a stale pgid can be reused by
     * an unrelated shell-uid process. A payload that already elevated itself runs as uid=0, which a
     * uid=2000 shell cannot signal — EPERM therefore means "still alive", not "gone".
     */
    public static final String PID_FILE = "/data/local/tmp/.lhasa_pid";

    /**
     * 阶段面包屑：每个会碰内核的动作开跑前写一次，成功后清空。
     *
     * payload 运行期间会按子阶段反复刷新（`payload-cred-3` 之类）。硬重启来不及写日志，
     * 但这份文件是崩溃**之前**写好的，下次启动读它就能定位到具体阶段。
     */
    public static final String STAGE_FILE = "/data/local/tmp/.lhasa_stage";

    /** 本次开机的失败记录：`<boot_id> <abort|permissive|enforcing>`。 */
    public static final String FAILED_FILE = "/data/local/tmp/.lhasa_failed_boot";

    /** 同开机 KASLR slide 缓存：`<boot_id> <slide|site> <value>`。 */
    public static final String SLIDE_CACHE_FILE = "/data/local/tmp/.lhasa_slide";

    /** timeout(1) 被触发时的退出码。 */
    public static final int TIMEOUT_EXIT = 124;

    private static final char BOOT_SEP = ':';
    private static final String BOOT_ID_READ = "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)";

    private static final String READ_PGID =
            "rec=$(cat " + PID_FILE + " 2>/dev/null); "
                    + "p=${rec%%" + BOOT_SEP + "*}; b=${rec##*" + BOOT_SEP + "}; "
                    + "now=" + BOOT_ID_READ + "; "
                    + "case \"$p\" in ''|*[!0-9]*) p=0 ;; esac; ";

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

    private static final String[] RETRY_MARKERS = {
            "leak failed",
            "unsupported kernel",
            "slide_probe failed",
            "[selinux] 3 consecutive misses, stop",
            "[selinux] 3 hits without effect, stop",
            "[cred] 6 consecutive misses, stop",
            "[cred] 3 attempts installed but not rooted, stop"
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

    /**
     * 99491 标记分类。优先级：中止 &gt; 成功 &gt; PARKED &gt; 可重试 &gt; 未命中。
     *
     * <p>中止必须赢过同一条 tail 里的成功标记（先 panic 后补打的输出不能算成功）；
     * 成功必须赢过 PARKED 信息行——成功 tail 里也有
     * `PARKED marker set`（本 boot 已 fire 的提示），那是"完事记得重启"，不是失败令牌。
     */
    public static Cve99491Outcome classifyCve99491(String tail) {
        if (tail == null || tail.isEmpty()) {
            return Cve99491Outcome.NONE;
        }
        if (containsAny(tail, CVE99491_ABORT_MARKERS)) {
            return Cve99491Outcome.ABORT_BOOT;
        }
        // The direct engine prints "PARKED marker set ..." on the success path too;
        // a live module (MODULE_LOADED + module_live=1 enforce=1) must win over the
        // generic PARKED line, otherwise a successful takeover is classified dirty.
        if (tail.contains("MODULE_LOADED")
                && tail.contains("module_live=1")
                && tail.contains("enforce=1")) {
            return Cve99491Outcome.SUCCESS;
        }
        if (isCve99491SuCheckOk(tail)) {
            return Cve99491Outcome.SUCCESS;
        }
        if (hasCve99491Parked(tail)) {
            return Cve99491Outcome.PARKED;
        }
        if (containsAny(tail, CVE99491_RETRY_MARKERS)) {
            return Cve99491Outcome.RETRY_SAFE;
        }
        return Cve99491Outcome.NONE;
    }

    /**
     * 99491 的 su 验收：两种形态都接受。
     *
     * <ul>
     *   <li>单行契约：`[f] su_check=uid=0 … u:r=ksu:s0`（旧/当前 exp）；</li>
     *   <li>块契约：`su_check_begin` 与 `su_check_end` 之间出现 uid=0 且 ksu 域（out12 之后的版本）。</li>
     * </ul>
     *
     * <p>`[f] su_check=FAILED` 不算成功（没有 uid=0/ksu 域）。
     */
    public static boolean isCve99491SuCheckOk(String tail) {
        if (tail == null) {
            return false;
        }
        boolean inBlock = false;
        StringBuilder block = new StringBuilder();
        for (String raw : tail.split("\\n")) {
            String line = raw.trim();
            if (line.contains("su_check_begin")) {
                inBlock = true;
                block.setLength(0);
                continue;
            }
            if (line.contains("su_check_end")) {
                inBlock = false;
                if (containsKsuIdentity(block.toString())) {
                    return true;
                }
                continue;
            }
            if (inBlock) {
                block.append(line).append(' ');
            }
            if (line.startsWith(CVE99491_SU_CHECK_PREFIX) && containsKsuIdentity(line)) {
                return true;
            }
        }
        return false;
    }

    /** `uid=0` + ksu 域（两种 SELinux 写法都接受）。 */
    public static boolean containsKsuIdentity(String output) {
        if (output == null || output.isEmpty()) {
            return false;
        }
        return output.contains("uid=0")
                && (output.contains(CVE99491_KSU_CONTEXT) || output.contains(CVE99491_KSU_CONTEXT_ALT));
    }

    /**
     * 是否出现真正的 PARKED 令牌。
     *
     * <p>direct 引擎失败时打印裸行 `PARKED`；成功/启动时打印
     * `[!] direct engine: PARKED marker set …` —— 后者是"本 boot 已 fire，记得重启"的信息，
     * 不算失败令牌（否则成功会被误判成失败）。
     */
    public static boolean hasCve99491Parked(String tail) {
        if (tail == null || tail.isEmpty()) {
            return false;
        }
        for (String raw : tail.split("\\n")) {
            String line = raw.trim();
            if (line.equals(CVE99491_PARKED) || line.startsWith(CVE99491_PARKED + " ")) {
                return true;
            }
            if (line.contains(CVE99491_PARKED_INFO)) {
                return true;
            }
        }
        return false;
    }

    /** 是否已出现任意"写内核之后"的标记（决定能否回退 98260）。 */
    public static boolean hasCve99491KernelWrite(String tail) {
        return containsAny(tail, CVE99491_WRITE_MARKERS);
    }

    public static boolean hasCve99491ModuleLive(String tail) {
        return tail != null && tail.contains(CVE99491_MODULE_LIVE);
    }

    public static boolean hasCve99491ModuleLoaded(String tail) {
        return tail != null && tail.contains(CVE99491_MODULE_LOADED);
    }

    /** 是否出现 99491 专属中止标记（panic / holding zombie / abort）。 */
    public static boolean hasCve99491Abort(String tail) {
        return containsAny(tail, CVE99491_ABORT_MARKERS);
    }

    /** getenforce 输出是否 Enforcing。 */
    public static boolean isEnforcing(String getenforce) {
        return getenforce != null && "Enforcing".equalsIgnoreCase(getenforce.trim());
    }

    /** /proc/modules 里是否已经出现 kernelsu（不管状态）。 */
    public static boolean hasKernelSuModule(String procModules) {
        if (procModules == null || procModules.trim().isEmpty()) {
            return false;
        }
        for (String raw : procModules.split("\\n")) {
            String line = raw.trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split("\\s+");
            if (parts.length > 0 && KSU_MODULE_NAME.equals(parts[0])) {
                return true;
            }
        }
        return false;
    }

    /** /proc/modules 里 kernelsu 是否 Live（模块加载完成、sucompat 可用）。 */
    public static boolean isKernelSuLive(String procModules) {
        if (procModules == null || procModules.trim().isEmpty()) {
            return false;
        }
        for (String raw : procModules.split("\\n")) {
            String line = raw.trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split("\\s+");
            if (parts.length > 0 && KSU_MODULE_NAME.equals(parts[0])
                    && line.contains(KSU_LIVE_TOKEN)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 99491 的干净开机预检（docs/99491-test-plan.md §5.3 + Lead 最终流程）：
     * 必须 Enforcing，且 /proc/modules 里没有 kernelsu。
     *
     * @return 空串 = 通过；否则是给用户看的具体拒绝原因（含"请重启"）
     */
    public static String cleanBootRefusal(String getenforce, String procModules) {
        return cleanBootRefusal(getenforce, procModules, false);
    }

    /**
     * @param sysModulePresent `/sys/module/kernelsu` 是否存在（/proc/modules 在部分 ROM 上
     *                         对 shell 不可读，用 sysfs 做第二来源）
     */
    public static String cleanBootRefusal(String getenforce, String procModules, boolean sysModulePresent) {
        StringBuilder reason = new StringBuilder();
        if (!isEnforcing(getenforce)) {
            String value = getenforce == null || getenforce.trim().isEmpty()
                    ? "未知" : getenforce.trim();
            reason.append("当前 SELinux=").append(value).append("（99491 要求 Enforcing）");
        }
        if (hasKernelSuModule(procModules) || sysModulePresent) {
            if (reason.length() > 0) {
                reason.append("；");
            }
            reason.append("/proc/modules 里已有 kernelsu（本次开机已被写过）");
        }
        if (reason.length() == 0) {
            return "";
        }
        return reason.append("。99491 必须从干净开机开始，请重启设备后再试；重启前不要重复点击")
                .toString();
    }

    /** `su -c id` 输出验收：uid=0 且 ksu 域（与 99491 的 su_check 契约一致）。 */
    public static boolean isKernelSuIdentityOk(String suOutput) {
        return containsKsuIdentity(suOutput);
    }

    /**
     * 写 99491 失败记录：`&lt;boot_id&gt; &lt;token&gt;`。
     *
     * <p>写进和 98260 同一个 {@link #FAILED_FILE}——两条链共享 dirty 标记：99491 写后失败后，
     * 98260 的 {@link #parseFailure} 也会因为未知 kind 而 BLOCKED，反之 98260 的 abort/enforcing
     * 记录也会让 99491 链在预检阶段被 {@link #hasDirtyBoot} 拦下。
     */
    public static String recordCve99491FailureCommand(String bootId, Cve99491Failure kind) {
        if (bootId == null || bootId.isEmpty()) {
            return "true";
        }
        String token = kind == null ? Cve99491Failure.WRITE_FAILURE.token : kind.token;
        return "echo '" + sanitize(bootId) + " " + token + "' > " + FAILED_FILE;
    }

    /**
     * 本次开机是否有任何一条链留下过 dirty 记录。
     *
     * <p>记录来自 98260 的 abort/enforcing/permissive，或 99491 的 dirty99491/parked99491。
     * 一旦有记录，说明内核对不上"干净状态"，99491 不能开跑。
     */
    public static boolean hasDirtyBoot(String failedFileContent, String currentBootId) {
        if (failedFileContent == null || failedFileContent.trim().isEmpty()) {
            return false;
        }
        String[] parts = failedFileContent.trim().split("\\s+");
        if (parts.length < 2) {
            return false;
        }
        if (currentBootId != null && !currentBootId.isEmpty()
                && !currentBootId.equals(parts[0])) {
            return false;
        }
        return true;
    }

    /** dirty boot 的人话原因；没有 dirty 记录时返回空串。 */
    public static String dirtyReason(String failedFileContent, String currentBootId) {
        if (!hasDirtyBoot(failedFileContent, currentBootId)) {
            return "";
        }
        String kind = failedFileContent.trim().split("\\s+")[1];
        switch (kind) {
            case "abort":
                return "本次开机已有提权链触发节点挂树/内核报错（abort），禁止再写内核";
            case "enforcing":
                return "本次开机 98260 已在写内核后失败（enforcing），内核状态不干净";
            case "permissive":
                return "本次开机 98260 已切入 SELinux 窗口（permissive），内核已被写过";
            case "dirty99491":
                return "本次开机 99491 已在写内核后失败（dirty99491），两条链共享 dirty 标记";
            case "parked99491":
                return "本次开机 99491 已 PARKED（parked99491），本 boot 不再写内核";
            default:
                return "本次开机已有失败记录（" + kind + "），本 boot 禁止再写内核";
        }
    }

    public static boolean isSupportedKernel(String kernel) {
        return KernelSupport.isSupported(kernel);
    }

    public static String kernelWarning(String kernel) {
        return "（警告）内核不在已验证 profile 表：" + kernel
                + " · 将按现有 offsets 继续尝试；若失败或内核异常，请重启后再试，不要在本次开机重复点击";
    }

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

    /** 把残留面包屑翻成人话；payload-<子阶段> 会展开成可读的步骤名。 */
    public static String leftoverStageHint(String stageFileContent) {
        if (stageFileContent == null || stageFileContent.trim().isEmpty()) {
            return "";
        }
        String[] parts = stageFileContent.trim().split("\\s+");
        String stage = parts[0];
        String label;
        if (stage.startsWith("payload")) {
            String detail = stage.length() > "payload".length()
                    ? stage.substring("payload".length()).replaceFirst("^[-_]", "")
                    : "";
            label = detail.isEmpty()
                    ? "主利用（uaf_plant_replay）"
                    : "主利用 · 具体阶段 " + describePayloadStage(detail);
        } else if (stage.startsWith("99491")) {
            label = describeCve99491Stage(stage);
        } else {
            switch (stage) {
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
        }
        return "上次运行停在「" + label + "」阶段，没有正常结束——如果是重启造成的，那就是这个阶段把设备带走的。";
    }

    private static String describeCve99491Stage(String stage) {
        String detail = stage.startsWith("99491-") ? stage.substring("99491-".length()) : stage;
        switch (detail) {
            case "profile":
            case "precheck":
                return "99491 预检/校验 profile（未写内核）";
            case "deploy":
                return "99491 资产部署（未写内核）";
            case "run":
                return "99491 分阶段二进制（real_cred 写原语/SELinux 窗口，可能已写内核）";
            case "write":
                return "99491 real_cred 写原语（已写内核）";
            case "selinux":
                return "99491 SELinux 切换窗口（已写内核）";
            case "ksu":
            case "module":
                return "99491 KernelSU late-load（已写内核）";
            case "final":
                return "99491 最终校验（su_check/module_live）";
            default:
                return "99491 · " + detail;
        }
    }

    private static String describePayloadStage(String detail) {
        if (detail.startsWith("task")) {
            return "task_struct 泄漏（task）";
        }
        if (detail.startsWith("selinux")) {
            return "清 SELinux（" + detail + "）";
        }
        if (detail.startsWith("cred")) {
            return "植入 cred（" + detail + "）";
        }
        if (detail.startsWith("exec")) {
            return "非 leader exec 竞态（exec）";
        }
        if (detail.startsWith("stream")) {
            return "order-1 页复用写入（stream）";
        }
        if (detail.startsWith("miss")) {
            return "页未命中，准备重试（page miss）";
        }
        if (detail.startsWith("rootd")) {
            return "启动 rootd（rootd）";
        }
        return detail;
    }

    private static String sanitize(String value) {
        if (value == null) {
            return "unknown";
        }
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    public static String launchCommand(String binary, String arguments, String logPath) {
        return "toybox setsid sh -c '" + binary + " " + arguments
                + " > " + logPath + " 2>&1 < /dev/null & echo \"$$" + BOOT_SEP + "\""
                + BOOT_ID_READ + " > " + PID_FILE
                + "' >/dev/null 2>&1 &";
    }

    public static String killCommand() {
        return "if [ -s " + PID_FILE + " ]; then "
                + READ_PGID
                + "if [ \"$b\" = \"$now\" ] && [ \"$p\" -gt 1 ]; then "
                + "kill -TERM -$p 2>/dev/null; sleep 1; kill -KILL -$p 2>/dev/null; "
                + "fi; rm -f " + PID_FILE + "; fi; true";
    }

    /** 接管成功后收掉临时 rootd：它已升权 uid=0，只能借 su 按 pgid 发信号。 */
    public static String suKillCommand() {
        return "if [ -s " + PID_FILE + " ]; then "
                + READ_PGID
                + "if [ -n \"$now\" ] && [ \"$b\" = \"$now\" ] && [ \"$p\" -gt 1 ]; then "
                + "/system/bin/su -c \"kill -TERM -$p 2>/dev/null; sleep 1; kill -KILL -$p 2>/dev/null; true\" 2>/dev/null; "
                + "fi; rm -f " + PID_FILE + "; "
                + "echo done; else echo none; fi";
    }

    public static String aliveCommand() {
        return "if [ -s " + PID_FILE + " ]; then "
                + READ_PGID
                + "if [ \"$b\" = \"$now\" ] && [ \"$p\" -gt 1 ]; then "
                + "err=$(kill -0 -$p 2>&1); rc=$?; "
                + "if [ $rc -eq 0 ] || echo \"$err\" | grep -qiE 'permitted|eperm|not owner'; then echo 1; "
                + "else rm -f " + PID_FILE + "; echo 0; fi; "
                + "else rm -f " + PID_FILE + "; echo 0; fi; "
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
