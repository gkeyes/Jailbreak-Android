package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * 99491 标记分类与 dirty boot 归因的验收（docs/99491-test-plan.md §10）。
 *
 * <p>98260 的分类（{@link BootGuard#classify(String)} / {@link BootGuard#parseFailure}）不受影响，
 * 这里只覆盖新增的 99491 通道。
 */
public class Cve99491MarkerTest {

    private static final String SUCCESS_TAIL =
            "[p] profile_ok release=6.18.21-android17-5-g805aa6adea19-abogki565292102-4k\n"
                    + "[p] anchor slide=0x10e7400000\n"
                    + "[+] swap uid=0 caps=full\n"
                    + "[+] cred == real_cred\n"
                    + "[+] setcon\n"
                    + "MODULE_LOADED\n"
                    + "[f] module_live=1 enforce=1\n"
                    + "[f] su_check=uid=0 context=u:r=ksu:s0";

    @Test
    public void fullSuccessTailClassifiesAsSuccess() {
        assertEquals(BootGuard.Cve99491Outcome.SUCCESS,
                BootGuard.classifyCve99491(SUCCESS_TAIL));
        assertTrue(BootGuard.isCve99491SuCheckOk(SUCCESS_TAIL));
        assertTrue(BootGuard.hasCve99491ModuleLive(SUCCESS_TAIL));
        assertTrue(BootGuard.hasCve99491ModuleLoaded(SUCCESS_TAIL));
    }

    @Test
    public void suCheckAcceptsBothSelinuxContextSpellings() {
        assertTrue(BootGuard.isCve99491SuCheckOk("[f] su_check=uid=0 u:r=ksu:s0"));
        assertTrue(BootGuard.isCve99491SuCheckOk("[f] su_check=uid=0 context=u:r:ksu:s0"));
        assertFalse(BootGuard.isCve99491SuCheckOk("[f] su_check=uid=2000 context=u:r=shell:s0"));
        assertFalse(BootGuard.isCve99491SuCheckOk("[f] su_check=uid=0 context=u:r:su:s0"));
    }

    @Test
    public void abortTailIsAbortBoot() {
        assertEquals(BootGuard.Cve99491Outcome.ABORT_BOOT,
                BootGuard.classifyCve99491("Kernel panic - not syncing"));
        assertEquals(BootGuard.Cve99491Outcome.ABORT_BOOT,
                BootGuard.classifyCve99491("[!] abort reason=holding zombie"));
        assertTrue(BootGuard.hasCve99491Abort("BUG: unable to handle kernel paging request"));
    }

    @Test
    public void abortWinsOverSuccessInTheSameTail() {
        String tail = SUCCESS_TAIL + "\nKernel panic - not syncing";
        assertEquals(BootGuard.Cve99491Outcome.ABORT_BOOT,
                BootGuard.classifyCve99491(tail));
    }

    @Test
    public void parkedTailIsParked() {
        assertEquals(BootGuard.Cve99491Outcome.PARKED,
                BootGuard.classifyCve99491("[p] profile_ok release=x\nPARKED reason=oracle miss"));
        assertEquals(BootGuard.Cve99491Outcome.PARKED,
                BootGuard.classifyCve99491("[+] swap uid=0\nPARKED"));
    }

    @Test
    public void retryTailIsRetrySafe() {
        assertEquals(BootGuard.Cve99491Outcome.RETRY_SAFE,
                BootGuard.classifyCve99491("PROFILE_MISMATCH release differs"));
        assertEquals(BootGuard.Cve99491Outcome.RETRY_SAFE,
                BootGuard.classifyCve99491("[p] profile_ok\nleak failed"));
        assertEquals(BootGuard.Cve99491Outcome.RETRY_SAFE,
                BootGuard.classifyCve99491("[p] oracle miss"));
    }

    @Test
    public void preWriteMarkersAloneAreNotSuccessOrRetry() {
        assertEquals(BootGuard.Cve99491Outcome.NONE,
                BootGuard.classifyCve99491("[p] profile_ok release=x\n[p] anchor slide=0x10e7400000"));
        assertEquals(BootGuard.Cve99491Outcome.NONE, BootGuard.classifyCve99491(""));
        assertEquals(BootGuard.Cve99491Outcome.NONE, BootGuard.classifyCve99491(null));
    }

    @Test
    public void kernelWriteMarkersAreRecognised() {
        assertTrue(BootGuard.hasCve99491KernelWrite("[+] swap uid=0"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[+] cred == real_cred"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[+] setcon"));
        assertTrue(BootGuard.hasCve99491KernelWrite("MODULE_LOADED"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[f] module_live=1 enforce=1"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[f] su_check=uid=0 u:r=ksu:s0"));
        assertFalse(BootGuard.hasCve99491KernelWrite("[p] profile_ok\n[p] anchor slide=0x1"));
        assertFalse(BootGuard.hasCve99491KernelWrite(""));
    }

    @Test
    public void failureRecordCarriesBootIdAndKind() {
        String writeFailure = BootGuard.recordCve99491FailureCommand(
                "boot-1", BootGuard.Cve99491Failure.WRITE_FAILURE);
        assertTrue(writeFailure, writeFailure.contains("boot-1 dirty99491"));
        assertTrue(writeFailure, writeFailure.contains(BootGuard.FAILED_FILE));

        String parked = BootGuard.recordCve99491FailureCommand(
                "boot-1", BootGuard.Cve99491Failure.PARKED);
        assertTrue(parked, parked.contains("boot-1 parked99491"));

        assertFalse(BootGuard.recordCve99491FailureCommand(
                "", BootGuard.Cve99491Failure.WRITE_FAILURE).contains(BootGuard.FAILED_FILE));
    }

    @Test
    public void dirtyBootIsSharedBetweenBothChains() {
        // 99491 写后失败 → 98260 的 parseFailure 也阻断（未知 kind → BLOCKED）
        assertEquals(BootGuard.Retry.BLOCKED,
                BootGuard.parseFailure("boot-1 dirty99491", "boot-1"));
        assertTrue(BootGuard.hasDirtyBoot("boot-1 dirty99491", "boot-1"));
        assertTrue(BootGuard.dirtyReason("boot-1 dirty99491", "boot-1").contains("99491"));

        // 98260 的写后失败 → 99491 预检必须拦下
        assertTrue(BootGuard.hasDirtyBoot("boot-1 enforcing", "boot-1"));
        assertTrue(BootGuard.dirtyReason("boot-1 enforcing", "boot-1").contains("98260"));
        assertTrue(BootGuard.hasDirtyBoot("boot-1 abort", "boot-1"));
        assertTrue(BootGuard.hasDirtyBoot("boot-1 permissive", "boot-1"));
        assertTrue(BootGuard.dirtyReason("boot-1 parked99491", "boot-1").contains("PARKED"));
    }

    @Test
    public void dirtyBootIgnoresOtherBootsAndMalformedRecords() {
        assertFalse(BootGuard.hasDirtyBoot("boot-old dirty99491", "boot-new"));
        assertFalse(BootGuard.hasDirtyBoot("", "boot-new"));
        assertFalse(BootGuard.hasDirtyBoot(null, "boot-new"));
        assertFalse(BootGuard.hasDirtyBoot("boot-new", "boot-new"));
        assertEquals("", BootGuard.dirtyReason("boot-old abort", "boot-new"));
    }

    @Test
    public void leftoverStageHintsCoverCve99491Breadcrumbs() {
        String run = BootGuard.leftoverStageHint("99491-run 1763803200000");
        assertTrue(run, run.contains("99491"));
        assertTrue(run, run.contains("重启"));

        String deploy = BootGuard.leftoverStageHint("99491-deploy 1763803200000");
        assertTrue(deploy, deploy.contains("部署"));

        String ksu = BootGuard.leftoverStageHint("99491-ksu 1763803200000");
        assertTrue(ksu, ksu.contains("KernelSU"));

        // 98260 的历史面包屑行为不变
        assertTrue(BootGuard.leftoverStageHint("payload-cred-2 1").contains("主利用"));
        assertTrue(BootGuard.leftoverStageHint("probe-slide 1").contains("slide_probe"));
    }
}
