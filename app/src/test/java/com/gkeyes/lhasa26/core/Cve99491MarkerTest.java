package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * 99491 标记分类、干净开机预检与 dirty boot 归因的验收
 * （docs/99491-test-plan.md §10 + Lead 最终设备流程：direct 引擎 --stage=root + ko 后端）。
 *
 * <p>98260 的分类（{@link BootGuard#classify(String)} / {@link BootGuard#parseFailure}）不受影响，
 * 这里只覆盖 99491 通道。
 */
public class Cve99491MarkerTest {

    private static final String PRE_WRITE =
            "[p] profile_ok release=6.18.21-android17-5-g805aa6adea19-abogki565292102-4k\n"
                    + "[p] anchor slide=0x10e7400000\n"
                    + "[p] engine=direct\n"
                    + "[!] direct engine: PARKED marker set for this boot; reboot before the next fire run";

    /** direct 引擎真实成功输出（ko 后端，out12 量级）。 */
    private static final String SUCCESS_TAIL = PRE_WRITE + "\n"
            + "[+] cred cand=0xffffff80524f2c00 euid=0 (uaf_writes=1)\n"
            + "[*] ids: uid=0 euid=0 gid=0 egid=0\n"
            + "[+] fsuid=0\n"
            + "[+] caps bit16(CAP_SYS_MODULE)\n"
            + "[!] permissive window opened at selinux_state-1 (fallback path)\n"
            + "[step] direct root: ko backend (patch ELF + finit_module)\n"
            + "[ko] ksud installed src=/data/local/tmp/ksud dst=/data/adb/ksud\n"
            + "[ko] image=/data/local/tmp/kernelsu-android17-6.18.ko size=375328\n"
            + "[ko] patched=225 missing=0 slide=0x2dc9000000\n"
            + "[ko] finit_module result=0 errno=0 (ok)\n"
            + "[+] ko backend loaded (rc=0)\n"
            + "MODULE_LOADED\n"
            + "[f] module_live=1 enforce=1\n"
            + "[*] module_live=1 enforce=1 ko_backend=1\n"
            + "[f] su_check=uid=0(root) gid=0(root) groups=0(root) context=u:r=ksu:s0\n"
            + "[!] direct engine complete: reboot required (PARKED marker set)";

    @Test
    public void fullSuccessTailClassifiesAsSuccess() {
        assertEquals(BootGuard.Cve99491Outcome.SUCCESS,
                BootGuard.classifyCve99491(SUCCESS_TAIL));
        assertTrue(BootGuard.isCve99491SuCheckOk(SUCCESS_TAIL));
        assertTrue(BootGuard.hasCve99491ModuleLive(SUCCESS_TAIL));
        assertTrue(BootGuard.hasCve99491ModuleLoaded(SUCCESS_TAIL));
    }

    /** 成功 tail 里的 "PARKED marker set" 是"记得重启"的信息行，不能盖掉成功。 */
    @Test
    public void successIsNotDowngradedByParkedInfoLine() {
        assertTrue(BootGuard.hasCve99491Parked(SUCCESS_TAIL));
        assertEquals(BootGuard.Cve99491Outcome.SUCCESS,
                BootGuard.classifyCve99491(SUCCESS_TAIL));
    }

    @Test
    public void suCheckAcceptsBothSelinuxContextSpellings() {
        assertTrue(BootGuard.isCve99491SuCheckOk("[f] su_check=uid=0 u:r=ksu:s0"));
        assertTrue(BootGuard.isCve99491SuCheckOk("[f] su_check=uid=0 context=u:r:ksu:s0"));
        assertFalse(BootGuard.isCve99491SuCheckOk("[f] su_check=uid=2000 context=u:r=shell:s0"));
        assertFalse(BootGuard.isCve99491SuCheckOk("[f] su_check=uid=0 context=u:r:su:s0"));
        assertFalse("FAILED 行不能算成功", BootGuard.isCve99491SuCheckOk("[f] su_check=FAILED"));
    }

    /** out12 之后的新形态：su_check_begin / su_check_end 包住 su 结果。 */
    @Test
    public void suCheckBlockFormIsAccepted() {
        String tail = PRE_WRITE + "\nMODULE_LOADED\n[f] module_live=1 enforce=1\n"
                + "su_check_begin\n"
                + "uid=0(root) gid=0(root) context=u:r:ksu:s0\n"
                + "su_check_end";
        assertTrue(BootGuard.isCve99491SuCheckOk(tail));
        assertEquals(BootGuard.Cve99491Outcome.SUCCESS, BootGuard.classifyCve99491(tail));
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
        assertEquals(BootGuard.Cve99491Outcome.ABORT_BOOT,
                BootGuard.classifyCve99491(SUCCESS_TAIL + "\nKernel panic - not syncing"));
    }

    @Test
    public void parkedTailIsParked() {
        String tail = PRE_WRITE + "\n[-] direct root: no euid-0 candidate\nPARKED";
        assertEquals(BootGuard.Cve99491Outcome.PARKED, BootGuard.classifyCve99491(tail));
        assertEquals(BootGuard.Cve99491Outcome.PARKED,
                BootGuard.classifyCve99491("[+] swap uid=0\nPARKED"));
    }

    @Test
    public void parkedMarkerInfoLineIsRecognised() {
        assertTrue(BootGuard.hasCve99491Parked("PARKED"));
        assertTrue(BootGuard.hasCve99491Parked("PARKED reason=oracle miss"));
        assertTrue(BootGuard.hasCve99491Parked(PRE_WRITE));
        assertFalse(BootGuard.hasCve99491Parked("[+] cred cand=0x1 euid=0"));
        assertFalse(BootGuard.hasCve99491Parked(null));
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
        assertTrue(BootGuard.hasCve99491KernelWrite("[+] cred cand=0x1 euid=0 (uaf_writes=1)"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[+] fsuid=0"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[+] caps bit16(CAP_SYS_MODULE)"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[+] setcon"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[!] permissive window opened at selinux_state-1"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[ko] finit_module result=0"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[step] direct root: ko backend"));
        assertTrue(BootGuard.hasCve99491KernelWrite("MODULE_LOADED"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[f] module_live=1 enforce=1"));
        assertTrue(BootGuard.hasCve99491KernelWrite("[f] su_check=uid=0 u:r=ksu:s0"));
        assertFalse(BootGuard.hasCve99491KernelWrite("[p] profile_ok\n[p] anchor slide=0x1"));
        assertFalse(BootGuard.hasCve99491KernelWrite(PRE_WRITE));
        assertFalse(BootGuard.hasCve99491KernelWrite(""));
    }

    // ---- 干净开机预检（Lead 最终流程：必须 Enforcing 且 /proc/modules 无 kernelsu） ----

    @Test
    public void enforcingDetection() {
        assertTrue(BootGuard.isEnforcing("Enforcing"));
        assertTrue(BootGuard.isEnforcing(" Enforcing\n"));
        assertFalse(BootGuard.isEnforcing("Permissive"));
        assertFalse(BootGuard.isEnforcing(""));
        assertFalse(BootGuard.isEnforcing(null));
    }

    @Test
    public void kernelSuModuleDetection() {
        String modules = "kernelsu 123456 0 - Live 0x0000000000000000 (O) 12345 1 - Live 0x0\n"
                + "wacom 1 0 - Live 0x0\n";
        assertTrue(BootGuard.hasKernelSuModule(modules));
        assertTrue(BootGuard.isKernelSuLive(modules));
        assertTrue(BootGuard.isKernelSuLive("kernelsu 123456 0 - Live 0x0"));
        assertFalse(BootGuard.isKernelSuLive("kernelsu 123456 0 - Loading 0x0"));
        assertFalse(BootGuard.hasKernelSuModule("wacom 1 0 - Live 0x0"));
        assertFalse(BootGuard.hasKernelSuModule(""));
        assertFalse(BootGuard.hasKernelSuModule(null));
    }

    @Test
    public void cleanBootIsAcceptedOnlyWhenEnforcingAndNoKernelSu() {
        assertEquals("", BootGuard.cleanBootRefusal("Enforcing", ""));
        assertEquals("", BootGuard.cleanBootRefusal("Enforcing", "wacom 1 0 - Live 0x0"));
        assertEquals("", BootGuard.cleanBootRefusal("Enforcing", "", false));
    }

    /** /proc/modules 不可读时用 /sys/module/kernelsu 做第二来源，仍然拒绝。 */
    @Test
    public void cleanBootRefusalUsesSysfsFallback() {
        String reason = BootGuard.cleanBootRefusal("Enforcing", "", true);
        assertTrue(reason, reason.contains("kernelsu"));
        assertTrue(reason, reason.contains("重启"));
    }

    @Test
    public void dirtyOrPermissiveBootIsRefusedWithRestartHint() {
        String permissive = BootGuard.cleanBootRefusal("Permissive", "");
        assertTrue(permissive, permissive.contains("SELinux=Permissive"));
        assertTrue(permissive, permissive.contains("重启"));

        String loaded = BootGuard.cleanBootRefusal("Enforcing", "kernelsu 1 0 - Live 0x0");
        assertTrue(loaded, loaded.contains("kernelsu"));
        assertTrue(loaded, loaded.contains("重启"));

        String both = BootGuard.cleanBootRefusal("Permissive", "kernelsu 1 0 - Live 0x0");
        assertTrue(both, both.contains("SELinux"));
        assertTrue(both, both.contains("kernelsu"));
    }

    @Test
    public void suIdentityAcceptanceMatchesContract() {
        assertTrue(BootGuard.isKernelSuIdentityOk(
                "uid=0(root) gid=0(root) groups=0(root) context=u:r=ksu:s0"));
        assertTrue(BootGuard.isKernelSuIdentityOk("uid=0 u:r:ksu:s0"));
        assertFalse(BootGuard.isKernelSuIdentityOk("uid=2000(shell) context=u:r:shell:s0"));
        assertFalse(BootGuard.isKernelSuIdentityOk("uid=0 root but no domain"));
    }

    // ---- dirty boot 归因（两条链共享） ----

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
        assertEquals(BootGuard.Retry.BLOCKED,
                BootGuard.parseFailure("boot-1 dirty99491", "boot-1"));
        assertTrue(BootGuard.hasDirtyBoot("boot-1 dirty99491", "boot-1"));
        assertTrue(BootGuard.dirtyReason("boot-1 dirty99491", "boot-1").contains("99491"));

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
