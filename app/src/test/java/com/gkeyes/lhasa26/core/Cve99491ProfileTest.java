package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Assume;
import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * 99491 profile 可用性判定（fail-closed）的纯逻辑验收。
 *
 * <p>契约：release 必须和设备 `uname -r` 精确相等且 verified=1 才启用；字段缺失/JSON 损坏/
 * release 不匹配/未 verified 一律禁用并给出原因。verified=0 只在 debug 构建（宿主显式开启）下
 * 允许带警告运行。
 */
public class Cve99491ProfileTest {

    private static final String RELEASE =
            "6.18.21-android17-5-g805aa6adea19-abogki565292102-4k";

    /** 和真实资产同 schema（format 是数字、verified 是 0/1）。 */
    private static String profileJson(int verified, String release) {
        return "{"
                + "\"format\": 1,"
                + "\"cve\": \"CVE-2026-99491\","
                + "\"release\": \"" + release + "\","
                + "\"verified\": " + verified + ","
                + "\"calibration\": {\"slide\": \"0x10e7400000\","
                + "\"pending\": [\"full chain validation\"]},"
                + "\"ts_off_cred\": 2312"
                + "}";
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    public void verifiedProfileOnMatchingReleaseIsAvailable() {
        byte[] raw = bytes(profileJson(1, RELEASE));
        Cve99491Profile.Status status = Cve99491Profile.check(RELEASE, raw, false);
        assertTrue(status.reason, status.available);
        assertEquals(RELEASE, status.release);
        assertEquals(Cve99491Profile.sha256(raw), status.sha256);
        assertEquals(64, status.sha256.length());
        assertTrue(status.reason, status.reason.contains("verified=1"));
    }

    @Test
    public void unverifiedProfileIsDisabledInReleaseBuilds() {
        Cve99491Profile.Status status =
                Cve99491Profile.check(RELEASE, bytes(profileJson(0, RELEASE)), false);
        assertFalse("verified=0 必须在 release 语义下禁用", status.available);
        assertTrue(status.reason, status.reason.contains("PROFILE_MISMATCH"));
        assertTrue(status.reason, status.reason.contains("verified=0"));
    }

    @Test
    public void unverifiedProfileIsAllowedOnlyWithExplicitDebugOptIn() {
        Cve99491Profile.Status status =
                Cve99491Profile.check(RELEASE, bytes(profileJson(0, RELEASE)), true);
        assertTrue(status.reason, status.available);
        assertTrue(status.reason, status.reason.contains("未 verified"));
    }

    @Test
    public void releaseMismatchIsDisabled() {
        Cve99491Profile.Status status = Cve99491Profile.check(
                "6.18.21-android17-5-gdeadbeef-abogki1-4k", bytes(profileJson(1, RELEASE)), false);
        assertFalse(status.available);
        assertTrue(status.reason, status.reason.contains("PROFILE_MISMATCH"));
        assertTrue(status.reason, status.reason.contains("release 不精确匹配"));
    }

    @Test
    public void missingAssetIsDisabledWithExplicitReason() {
        Cve99491Profile.Status status = Cve99491Profile.check(RELEASE, null, true);
        assertFalse(status.available);
        assertTrue(status.reason, status.reason.contains("PROFILE_MISSING"));
        assertTrue(status.reason, status.reason.contains(Cve99491Profile.ASSET_NAME));
        assertEquals("", status.release);
    }

    @Test
    public void corruptedJsonIsDisabledNotCrashing() {
        Cve99491Profile.Status status = Cve99491Profile.check(RELEASE, bytes("{ this is not json"), true);
        assertFalse(status.available);
        assertTrue(status.reason, status.reason.contains("PROFILE_MISMATCH"));
    }

    @Test
    public void missingFieldsAreDisabled() {
        Cve99491Profile.Status noRelease = Cve99491Profile.check(
                RELEASE, bytes("{\"format\":1,\"cve\":\"CVE-2026-99491\",\"verified\":1}"), true);
        assertFalse(noRelease.available);
        assertTrue(noRelease.reason, noRelease.reason.contains("release"));

        Cve99491Profile.Status noFormat = Cve99491Profile.check(
                RELEASE, bytes("{\"cve\":\"CVE-2026-99491\",\"release\":\"" + RELEASE + "\",\"verified\":1}"), true);
        assertFalse(noFormat.available);
        assertTrue(noFormat.reason, noFormat.reason.contains("format"));

        Cve99491Profile.Status noVerified = Cve99491Profile.check(
                RELEASE, bytes("{\"format\":1,\"cve\":\"CVE-2026-99491\",\"release\":\"" + RELEASE + "\"}"), true);
        assertFalse(noVerified.available);
        assertTrue(noVerified.reason, noVerified.reason.contains("verified"));
    }

    @Test
    public void wrongFormatOrCveIsDisabled() {
        String wrongFormat = profileJson(1, RELEASE).replace("\"format\": 1", "\"format\": 2");
        Cve99491Profile.Status format = Cve99491Profile.check(RELEASE, bytes(wrongFormat), true);
        assertFalse(format.available);
        assertTrue(format.reason, format.reason.contains("format"));

        String wrongCve = profileJson(1, RELEASE).replace("CVE-2026-99491", "CVE-2026-99999");
        Cve99491Profile.Status cve = Cve99491Profile.check(RELEASE, bytes(wrongCve), true);
        assertFalse(cve.available);
        assertTrue(cve.reason, cve.reason.contains("cve"));
    }

    @Test
    public void acceptedFormatBothStyles() {
        String semanticFormat = profileJson(1, RELEASE)
                .replace("\"format\": 1", "\"format\": \"lhasa-99491-profile/1\"");
        Cve99491Profile.Status status =
                Cve99491Profile.check(RELEASE, bytes(semanticFormat), false);
        assertTrue(status.reason, status.available);
    }

    @Test
    public void unknownDeviceReleaseIsDisabled() {
        Cve99491Profile.Status status = Cve99491Profile.check("", bytes(profileJson(1, RELEASE)), false);
        assertFalse("读不到内核版本时必须 fail-closed", status.available);
        assertTrue(status.reason, status.reason.contains("PROFILE_MISMATCH"));
        Cve99491Profile.Status nullRelease = Cve99491Profile.check(null, bytes(profileJson(1, RELEASE)), false);
        assertFalse(nullRelease.available);
    }

    @Test
    public void parseExposesTopLevelFieldsOnly() {
        Cve99491Profile.Loaded loaded = Cve99491Profile.parse(bytes(profileJson(0, RELEASE)));
        assertTrue(loaded.error, loaded.isOk());
        assertNotNull(loaded.profile);
        assertEquals(RELEASE, loaded.profile.release());
        assertEquals(Cve99491Profile.EXPECTED_CVE, loaded.profile.cve());
        assertEquals("1", loaded.profile.format());
        assertFalse(loaded.profile.isVerified());
        assertEquals(Cve99491Profile.sha256(bytes(profileJson(0, RELEASE))), loaded.sha256);
    }

    @Test
    public void booleanVerifiedIsAcceptedToo() {
        String json = profileJson(1, RELEASE).replace("\"verified\": 1", "\"verified\": true");
        Cve99491Profile.Status status = Cve99491Profile.check(RELEASE, bytes(json), false);
        assertTrue(status.reason, status.available);
    }

    @Test
    public void sha256MatchesKnownVector() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Cve99491Profile.sha256("abc".getBytes(StandardCharsets.UTF_8)));
        assertEquals("", Cve99491Profile.sha256(null));
    }

    /**
     * 对仓库里真实资产做一次冒烟解析（assets 由 Lead 维护，不能改动）。
     * 单元测试工作目录是 app/；文件不在时跳过，避免测试和资产生命周期耦合。
     */
    @Test
    public void realRepositoryAssetParses() throws Exception {
        File asset = new File("src/main/assets/" + Cve99491Profile.ASSET_NAME);
        Assume.assumeTrue("repo asset 不存在，跳过", asset.isFile());
        byte[] raw = Files.readAllBytes(asset.toPath());
        Cve99491Profile.Loaded loaded = Cve99491Profile.parse(raw);
        assertTrue(String.valueOf(loaded.error), loaded.isOk());
        assertEquals(Cve99491Profile.EXPECTED_CVE, loaded.profile.cve());
        assertTrue("release 必须像 uname -r", loaded.profile.release().startsWith("6.18.21"));
        // 真机标定未完成时 verified=0：严格模式必须禁用，debug 才能在显式放宽下运行
        boolean strictAvailable =
                Cve99491Profile.check(loaded.profile.release(), raw, false).available;
        boolean debugAvailable =
                Cve99491Profile.check(loaded.profile.release(), raw, true).available;
        assertEquals(loaded.profile.isVerified(), strictAvailable);
        assertTrue(debugAvailable);
    }
}
