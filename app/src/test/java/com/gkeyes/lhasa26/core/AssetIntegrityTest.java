package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * 资产完整性（size + sha256）的纯逻辑验收。
 *
 * <p>背景：99491 的最终流程要部署 exp/ko/ksud，其中 ksud 4.9 MB、ko 375 KB 走按需投放；
 * 一旦"设备上的旧文件被当成新文件"或"传输损坏"，后面的提权链会跑在错误字节上。
 * 校验规则 fail-closed：期望值已知且不匹配就拒绝部署/执行。
 */
public class AssetIntegrityTest {

    @Test
    public void ksudContractMatchesLedger() {
        assertEquals(4990848L, AssetIntegrity.KSUD_BYTES);
        assertEquals("4f7d5fd65631915ea579ff406bd9cbe58217f2c91dac6527f5b2f28ad4508171",
                AssetIntegrity.KSUD_SHA256);
        assertEquals(64, AssetIntegrity.KSUD_SHA256.length());
        assertTrue(AssetIntegrity.hasExpectations(AssetIntegrity.KSUD_ASSET));
    }

    @Test
    public void koContractMatchesLedger() {
        assertEquals(375328L, AssetIntegrity.KSU_KO_BYTES);
        assertEquals("kernelsu-android17-6.18.ko", AssetIntegrity.KSU_KO_ASSET);
        assertEquals("d848bcbeb3f4daffeea4b2ad2d70aac8f79211ce9f15f200dd87c7b8d68ebe30",
                AssetIntegrity.KSU_KO_SHA256);
        assertTrue(AssetIntegrity.hasExpectations(AssetIntegrity.KSU_KO_ASSET));
        assertTrue(AssetIntegrity.verify(AssetIntegrity.KSU_KO_ASSET,
                AssetIntegrity.KSU_KO_BYTES, AssetIntegrity.KSU_KO_SHA256).isOk());
        assertEquals(AssetIntegrity.Result.SHA_MISMATCH,
                AssetIntegrity.verify(AssetIntegrity.KSU_KO_ASSET,
                        AssetIntegrity.KSU_KO_BYTES, "deadbeef").result);
    }

    @Test
    public void expContractMatchesLedger() {
        assertEquals(800696L, AssetIntegrity.CVE99491_EXP_BYTES);
        assertEquals("2b8843ce5b1498e2f20f56933c9533808c16194283717e4a61dcf5de7359b921",
                AssetIntegrity.CVE99491_EXP_SHA256);
        assertTrue(AssetIntegrity.hasExpectations(AssetIntegrity.CVE99491_EXP_ASSET));
        assertTrue(AssetIntegrity.verify(AssetIntegrity.CVE99491_EXP_ASSET,
                AssetIntegrity.CVE99491_EXP_BYTES,
                AssetIntegrity.CVE99491_EXP_SHA256).isOk());
        assertEquals(AssetIntegrity.Result.SIZE_MISMATCH,
                AssetIntegrity.verify(AssetIntegrity.CVE99491_EXP_ASSET, 1L, "").result);
    }

    @Test
    public void matchingSizeAndHashIsOk() {
        AssetIntegrity.Verdict verdict = AssetIntegrity.verify(
                4990848L, AssetIntegrity.KSUD_SHA256, 4990848L, AssetIntegrity.KSUD_SHA256, "ksud");
        assertTrue(verdict.isOk());
        assertTrue(verdict.detail, verdict.detail.contains("校验通过"));
    }

    @Test
    public void sizeMismatchIsRejected() {
        AssetIntegrity.Verdict verdict = AssetIntegrity.verify(AssetIntegrity.KSUD_ASSET,
                4990847L, AssetIntegrity.KSUD_SHA256);
        assertEquals(AssetIntegrity.Result.SIZE_MISMATCH, verdict.result);
        assertTrue(verdict.detail, verdict.detail.contains("大小不匹配"));
    }

    @Test
    public void shaMismatchIsRejected() {
        AssetIntegrity.Verdict verdict = AssetIntegrity.verify(AssetIntegrity.KSUD_ASSET,
                AssetIntegrity.KSUD_BYTES, "deadbeef");
        assertEquals(AssetIntegrity.Result.SHA_MISMATCH, verdict.result);
        assertTrue(verdict.detail, verdict.detail.contains("sha256 不匹配"));
    }

    @Test
    public void missingActualHashIsRejectedWhenExpected() {
        AssetIntegrity.Verdict verdict = AssetIntegrity.verify(
                AssetIntegrity.KSUD_BYTES, AssetIntegrity.KSUD_SHA256,
                AssetIntegrity.KSUD_BYTES, "", "ksud");
        assertEquals(AssetIntegrity.Result.SHA_MISMATCH, verdict.result);
        assertTrue(verdict.detail, verdict.detail.contains("拿不到 sha256"));
    }

    @Test
    public void unknownExpectationsDoNotBlock() {
        AssetIntegrity.Verdict verdict = AssetIntegrity.verify(0L, "", 1234L, "whatever", "unknown");
        assertTrue(verdict.isOk());
        // 未登记期望值的资产（如 98260 的探针）不做大小/哈希校验
        assertTrue(AssetIntegrity.verify("slide_probe", 43448L, "").isOk());
    }

    /** 远端拿不到 sha（sha256sum 不可用）时按"不能证明是期望版本"处理：会触发重投。 */
    @Test
    public void koMissingRemoteHashIsRejected() {
        AssetIntegrity.Verdict verdict = AssetIntegrity.verify(
                AssetIntegrity.KSU_KO_ASSET, AssetIntegrity.KSU_KO_BYTES, "");
        assertEquals(AssetIntegrity.Result.SHA_MISMATCH, verdict.result);
    }

    @Test
    public void sha256HexMatchesKnownVector() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                AssetIntegrity.sha256Hex("abc".getBytes(StandardCharsets.UTF_8)));
        assertEquals("", AssetIntegrity.sha256Hex(null));
        assertEquals("", AssetIntegrity.toHex(null));
    }

    @Test
    public void sha256MatchesIsCaseInsensitiveAndEmptyTolerant() {
        String upper = AssetIntegrity.KSUD_SHA256.toUpperCase(java.util.Locale.US);
        assertTrue(AssetIntegrity.sha256Matches(upper, AssetIntegrity.KSUD_SHA256));
        assertTrue(AssetIntegrity.sha256Matches("anything", ""));
        assertFalse(AssetIntegrity.sha256Matches("deadbeef", AssetIntegrity.KSUD_SHA256));
    }
}
