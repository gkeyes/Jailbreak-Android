package com.gkeyes.lhasa26.core;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * APK 内原生资产的完整性契约（大小 + sha256）。
 *
 * <p>设备的提权链依赖 4 个原生资产：98260 的三个探针、以及 99491 的
 * {@code cve99491_exp} / {@code lhasa_99491_profile.json} /
 * {@code kernelsu-android17-6.18.ko} / {@code ksud}。其中 ksud 与 ko 是"按需投放"的
 * 大文件：设备上已有同内容文件时不该重传 4.9 MB，重传前也必须确认 APK 里的字节就是
 * 校验过的那个版本。校验规则 fail-closed：期望值已知时不匹配就拒绝部署。
 *
 * <p>sha256 期望值来源：{@code tools/assets-ledger.json}（Ledger 由 Lead 维护；本类只读常量
 * 镜像，改资产/改 ledger 时必须同步这里）。{@code cve99491_exp} 若在真机验收后重新构建，
 * Lead 会给出新 size/sha256，这里同步更新即可自动启用新的哈希校验。
 *
 * <p>纯逻辑（无 Android 依赖），JVM 单测覆盖。
 */
public final class AssetIntegrity {

    public static final String KSUD_ASSET = "ksud";
    public static final String KSU_KO_ASSET = "kernelsu-android17-6.18.ko";
    public static final String CVE99491_EXP_ASSET = "cve99491_exp";

    /** ksud：KernelSU v3.3.1 libksud.so（tools/assets-ledger.json, size+sha256 权威值）。 */
    public static final long KSUD_BYTES = 4990848L;
    public static final String KSUD_SHA256 =
            "4f7d5fd65631915ea579ff406bd9cbe58217f2c91dac6527f5b2f28ad4508171";

    /** kernelsu ko（KMI android17-6.18）：375328 B，Lead 真机验收的最终产物。 */
    public static final long KSU_KO_BYTES = 375328L;
    public static final String KSU_KO_SHA256 =
            "d848bcbeb3f4daffeea4b2ad2d70aac8f79211ce9f15f200dd87c7b8d68ebe30";

    /** 99491 最终 exp（out12 构建，direct 引擎 + ko 后端）。 */
    public static final long CVE99491_EXP_BYTES = 800696L;
    public static final String CVE99491_EXP_SHA256 =
            "9f29827ff9a6976e4ebfa44bd562c640e47b6fc12be7abf71d79959481c6ff9a";

    /** profile 由 Lead 在 S6/S7 后改 verified=1，size/sha 会变：不做硬编码校验，只用运行时解析。 */
    public static final long PROFILE_BYTES = 0L;
    public static final String PROFILE_SHA256 = "";

    public enum Result {
        /** 期望值未知或全部匹配。 */
        OK,
        /** 已知期望大小且不一致。 */
        SIZE_MISMATCH,
        /** 已知期望 sha256 且不一致。 */
        SHA_MISMATCH
    }

    /** 校验结论；{@link #detail} 直接进日志（不含敏感内容，只有大小/哈希前缀）。 */
    public static final class Verdict {
        public final Result result;
        public final String detail;

        Verdict(Result result, String detail) {
            this.result = result;
            this.detail = detail == null ? "" : detail;
        }

        public boolean isOk() {
            return result == Result.OK;
        }
    }

    private AssetIntegrity() {
    }

    /** 已知期望大小；0 表示未知。 */
    public static long expectedSize(String assetName) {
        if (KSUD_ASSET.equals(assetName)) {
            return KSUD_BYTES;
        }
        if (KSU_KO_ASSET.equals(assetName)) {
            return KSU_KO_BYTES;
        }
        if (CVE99491_EXP_ASSET.equals(assetName)) {
            return CVE99491_EXP_BYTES;
        }
        if (Cve99491Profile.ASSET_NAME.equals(assetName)) {
            return PROFILE_BYTES;
        }
        return 0L;
    }

    /** 已知期望 sha256（小写十六进制）；空串表示未知。 */
    public static String expectedSha256(String assetName) {
        if (KSUD_ASSET.equals(assetName)) {
            return KSUD_SHA256;
        }
        if (KSU_KO_ASSET.equals(assetName)) {
            return KSU_KO_SHA256;
        }
        if (CVE99491_EXP_ASSET.equals(assetName)) {
            return CVE99491_EXP_SHA256;
        }
        if (Cve99491Profile.ASSET_NAME.equals(assetName)) {
            return PROFILE_SHA256;
        }
        return "";
    }

    /** 是否配置了任何可校验的期望值（决定"按需投放"能否跳过重传）。 */
    public static boolean hasExpectations(String assetName) {
        return expectedSize(assetName) > 0L || !expectedSha256(assetName).isEmpty();
    }

    /** 用本类内置期望值校验资产（本地字节或远端文件）。 */
    public static Verdict verify(String assetName, long actualSize, String actualSha256) {
        return verify(expectedSize(assetName), expectedSha256(assetName),
                actualSize, actualSha256, assetName);
    }

    /**
     * 可注入期望值的校验（单测用；生产走 {@link #verify(String, long, String)}）。
     */
    public static Verdict verify(long expectedSize, String expectedSha256,
                                 long actualSize, String actualSha256, String label) {
        String tag = label == null || label.isEmpty() ? "asset" : label;
        if (expectedSize > 0L && expectedSize != actualSize) {
            return new Verdict(Result.SIZE_MISMATCH, tag + " 大小不匹配：期望 " + expectedSize
                    + " B，实际 " + actualSize + " B");
        }
        String expectedHash = normalize(expectedSha256);
        if (!expectedHash.isEmpty()) {
            String actualHash = normalize(actualSha256);
            if (actualHash.isEmpty()) {
                return new Verdict(Result.SHA_MISMATCH, tag + " 拿不到 sha256（sha256sum 不可用？），"
                        + "期望 " + shortHash(expectedHash));
            }
            if (!expectedHash.equals(actualHash)) {
                return new Verdict(Result.SHA_MISMATCH, tag + " sha256 不匹配：期望 "
                        + shortHash(expectedHash) + "，实际 " + shortHash(actualHash));
            }
        }
        return new Verdict(Result.OK, tag + " 校验通过（size=" + actualSize + " B"
                + (expectedHash.isEmpty() ? "" : "，sha256=" + shortHash(expectedHash)) + "）");
    }

    /** sha256 是否匹配；期望值为空 = 不校验（返回 true）。 */
    public static boolean sha256Matches(String actualSha256, String expectedSha256) {
        String expected = normalize(expectedSha256);
        return expected.isEmpty() || expected.equals(normalize(actualSha256));
    }

    /** 字节数组的 sha256（小写十六进制）；null 返回空串。 */
    public static String sha256Hex(byte[] raw) {
        if (raw == null) {
            return "";
        }
        try {
            return toHex(MessageDigest.getInstance("SHA-256").digest(raw));
        } catch (NoSuchAlgorithmException unsupported) {
            return "";
        }
    }

    /** 已完成的 MessageDigest 结果转小写十六进制。 */
    public static String toHex(byte[] hash) {
        if (hash == null || hash.length == 0) {
            return "";
        }
        StringBuilder out = new StringBuilder(hash.length * 2);
        for (byte value : hash) {
            int unsigned = value & 0xff;
            if (unsigned < 0x10) {
                out.append('0');
            }
            out.append(Integer.toHexString(unsigned));
        }
        return out.toString();
    }

    private static String normalize(String sha256) {
        if (sha256 == null) {
            return "";
        }
        return sha256.trim().toLowerCase(Locale.US);
    }

    private static String shortHash(String sha256) {
        if (sha256 == null || sha256.isEmpty()) {
            return "?";
        }
        return sha256.length() <= 16 ? sha256 : sha256.substring(0, 16) + "…";
    }
}
