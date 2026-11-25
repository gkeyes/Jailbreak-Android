package com.gkeyes.lhasa26.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * CVE-2026-99491 profile（`lhasa_99491_profile.json`）的只读校验。
 *
 * <p>约定（docs/99491-test-plan.md §10）：profile 是唯一事实源，顶层字段
 * {@code format/cve/release/verified} 决定这条链能不能用。规则是 fail-closed：
 * <ul>
 *   <li>{@code release} 必须和设备 {@code uname -r} 精确相等（内核 build 不同 = 常量不同）；</li>
 *   <li>{@code verified} 必须为 {@code true}（标定通过、双来源校验完成）；</li>
 *   <li>资产缺失 / JSON 损坏 / 字段缺失一律不可用，绝不放行。</li>
 * </ul>
 *
 * <p>本类刻意不依赖 Android：profile 解析、可用性判定、sha256 都是纯逻辑，
 * 可以在 JVM 单测里覆盖（AssetManager 的读取留在 {@link WorkflowEngine}）。
 */
public final class Cve99491Profile {

    /** APK 内资产名；部署到 /data/local/tmp 后同名。 */
    public static final String ASSET_NAME = "lhasa_99491_profile.json";
    public static final String EXPECTED_CVE = "CVE-2026-99491";
    /**
     * 生成器写的是数字 1（见 app/src/main/assets/lhasa_99491_profile.json）；
     * 同时接受带语义的字符串形式，方便以后改 schema 时不至于把已验证资产判死。
     */
    public static final String EXPECTED_FORMAT = "1";
    private static final String[] ACCEPTED_FORMATS = {"1", "lhasa-99491-profile/1"};
    public static final int SHA256_HEX_LENGTH = 64;

    private final String format;
    private final String cve;
    private final String release;
    private final boolean verified;
    private final String sha256;

    private Cve99491Profile(String format, String cve, String release, boolean verified, String sha256) {
        this.format = format;
        this.cve = cve;
        this.release = release;
        this.verified = verified;
        this.sha256 = sha256;
    }

    public String format() {
        return format;
    }

    public String cve() {
        return cve;
    }

    public String release() {
        return release;
    }

    public boolean isVerified() {
        return verified;
    }

    /** 资产原始字节的 sha256（小写十六进制）；不可读时为空串。 */
    public String sha256() {
        return sha256;
    }

    /** profile 解析结果：成功时 {@code profile != null} 且 {@code error} 为空。 */
    public static final class Loaded {
        public final Cve99491Profile profile;
        public final String sha256;
        public final String error;

        Loaded(Cve99491Profile profile, String sha256, String error) {
            this.profile = profile;
            this.sha256 = sha256 == null ? "" : sha256;
            this.error = error == null ? "" : error;
        }

        public boolean isOk() {
            return profile != null && error.isEmpty();
        }
    }

    /**
     * 可用性判定结果。{@link #available} 为 true 才允许运行 99491 链；
     * 否则 {@link #reason} 是给用户/日志看的具体原因（含 {@code PROFILE_MISMATCH} 或 {@code PROFILE_MISSING} 标记）。
     */
    public static final class Status {
        public final boolean available;
        public final String reason;
        /** profile 声明的 release；不可读时为空串。 */
        public final String release;
        public final String sha256;

        Status(boolean available, String reason, String release, String sha256) {
            this.available = available;
            this.reason = reason == null ? "" : reason;
            this.release = release == null ? "" : release;
            this.sha256 = sha256 == null ? "" : sha256;
        }
    }

    /**
     * 解析资产字节并判定可用性。设备 release 为空（未取到 kernel）同样 fail-closed。
     *
     * <p>等价于 {@code check(deviceRelease, raw, false)}：release 构建 / 单测的严格模式。
     *
     * @param deviceRelease `uname -r` 的结果，可空
     * @param raw           profile 资产的原始字节，可空（表示资产不存在）
     */
    public static Status check(String deviceRelease, byte[] raw) {
        return check(deviceRelease, raw, false);
    }

    /**
     * @param deviceRelease   `uname -r` 的结果
     * @param raw             profile 资产原始字节
     * @param allowUnverified debug 构建允许 {@code verified=0} 的 profile 带警告运行
     *                        （真机标定阶段用；release 构建必须传 false，fail-closed）
     */
    public static Status check(String deviceRelease, byte[] raw, boolean allowUnverified) {
        Loaded loaded = parse(raw);
        if (!loaded.isOk()) {
            return new Status(false, loaded.error, "", loaded.sha256);
        }
        return loaded.profile.checkAgainst(deviceRelease, allowUnverified);
    }

    /** 解析 profile JSON；失败时 `error` 是明确原因而不是抛异常。 */
    public static Loaded parse(byte[] raw) {
        if (raw == null || raw.length == 0) {
            return new Loaded(null, "", "PROFILE_MISSING：资产 " + ASSET_NAME + " 不存在或为空"
                    + "（需要构建时放入 app/src/main/assets/）");
        }
        String sha = sha256(raw);
        String json = new String(raw, StandardCharsets.UTF_8);
        String format = topLevelScalar(json, "format");
        String cve = topLevelScalar(json, "cve");
        String release = topLevelScalar(json, "release");
        String verifiedValue = topLevelScalar(json, "verified");
        if (format == null || format.trim().isEmpty()) {
            return new Loaded(null, sha, "PROFILE_MISMATCH：缺少 format 字段（fail-closed）");
        }
        if (cve == null || cve.trim().isEmpty()) {
            return new Loaded(null, sha, "PROFILE_MISMATCH：缺少 cve 字段（fail-closed）");
        }
        if (release == null || release.trim().isEmpty()) {
            return new Loaded(null, sha, "PROFILE_MISMATCH：缺少 release 字段（fail-closed）");
        }
        if (verifiedValue == null) {
            return new Loaded(null, sha, "PROFILE_MISMATCH：缺少 verified 字段（fail-closed）");
        }
        boolean verified = isTruthy(verifiedValue);
        Cve99491Profile profile = new Cve99491Profile(
                format.trim(), cve.trim(), release.trim(), verified, sha);
        return new Loaded(profile, sha, "");
    }

    /** 逐项校验：format → cve → verified（debug 可放宽 warning）→ release 精确匹配。 */
    public Status checkAgainst(String deviceRelease) {
        return checkAgainst(deviceRelease, false);
    }

    /** @see #check(String, byte[], boolean) */
    public Status checkAgainst(String deviceRelease, boolean allowUnverified) {
        if (!isAcceptedFormat(format)) {
            return new Status(false, "PROFILE_MISMATCH：format=" + format
                    + "，期望 " + EXPECTED_FORMAT + "（fail-closed）", release, sha256);
        }
        if (!EXPECTED_CVE.equalsIgnoreCase(cve)) {
            return new Status(false, "PROFILE_MISMATCH：cve=" + cve
                    + "，期望 " + EXPECTED_CVE + "（fail-closed）", release, sha256);
        }
        if (!verified && !allowUnverified) {
            return new Status(false, "PROFILE_MISMATCH：verified=0，只有标定完成"
                    + "（双来源校验通过）才允许启用；debug 构建可带警告运行（release fail-closed）",
                    release, sha256);
        }
        String device = deviceRelease == null ? "" : deviceRelease.trim();
        if (device.isEmpty()) {
            return new Status(false, "PROFILE_MISMATCH：读不到设备内核版本（Shizuku 未授权？）"
                    + "，无法做 release 精确匹配（fail-closed）", release, sha256);
        }
        if (!release.equals(device)) {
            return new Status(false, "PROFILE_MISMATCH：release 不精确匹配"
                    + "（profile=" + release + "，设备=" + device + "）（fail-closed）", release, sha256);
        }
        if (!verified) {
            return new Status(true, "未 verified（仅 debug 放宽）：release=" + release
                    + " · 真机可能失败/重启，请尽快完成标定", release, sha256);
        }
        return new Status(true, "profile 通过：release=" + release + " · verified=1",
                release, sha256);
    }

    /** profile 的 verified 字段可能是 1/0（生成器写数字）或 true/false；其余一律 false。 */
    private static boolean isTruthy(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = value.trim();
        return "1".equals(trimmed) || "true".equalsIgnoreCase(trimmed);
    }

    static boolean isAcceptedFormat(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = value.trim();
        for (String accepted : ACCEPTED_FORMATS) {
            if (accepted.equalsIgnoreCase(trimmed)) {
                return true;
            }
        }
        return false;
    }

    /** 小写十六进制 sha256；null/空输入返回空串。 */
    public static String sha256(byte[] raw) {
        if (raw == null) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw);
            StringBuilder out = new StringBuilder(hash.length * 2);
            for (byte value : hash) {
                int unsigned = value & 0xff;
                if (unsigned < 0x10) {
                    out.append('0');
                }
                out.append(Integer.toHexString(unsigned));
            }
            return out.toString();
        } catch (NoSuchAlgorithmException unsupported) {
            return "";
        }
    }

    /**
     * 只取顶层标量字段。profile 来自本仓库生成器（tools/99491/gen_profile.py），
     * 格式受控，不需要完整 JSON 解析器；但绝不能因为嵌套字段而误读，所以要求
     * 键后的下一个非空白字符是冒号，值支持字符串/数字/布尔/裸 token。
     */
    private static String topLevelScalar(String json, String key) {
        if (json == null || key == null) {
            return null;
        }
        String needle = "\"" + key + "\"";
        int from = 0;
        while (from < json.length()) {
            int index = json.indexOf(needle, from);
            if (index < 0) {
                return null;
            }
            int afterKey = index + needle.length();
            int colon = skipWhitespace(json, afterKey);
            if (colon >= json.length() || json.charAt(colon) != ':') {
                from = afterKey;
                continue;
            }
            int valueStart = skipWhitespace(json, colon + 1);
            return readValue(json, valueStart);
        }
        return null;
    }

    private static int skipWhitespace(String text, int from) {
        int index = from;
        while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
            index++;
        }
        return index;
    }

    private static String readValue(String json, int start) {
        if (start < 0 || start >= json.length()) {
            return null;
        }
        char first = json.charAt(start);
        if (first == '"') {
            StringBuilder value = new StringBuilder();
            int index = start + 1;
            while (index < json.length()) {
                char current = json.charAt(index);
                if (current == '\\' && index + 1 < json.length()) {
                    value.append(json.charAt(index + 1));
                    index += 2;
                    continue;
                }
                if (current == '"') {
                    return value.toString();
                }
                value.append(current);
                index++;
            }
            return null;
        }
        int end = start;
        while (end < json.length()) {
            char current = json.charAt(end);
            if (current == ',' || current == '}' || current == ']'
                    || Character.isWhitespace(current)) {
                break;
            }
            end++;
        }
        return end == start ? null : json.substring(start, end);
    }
}
