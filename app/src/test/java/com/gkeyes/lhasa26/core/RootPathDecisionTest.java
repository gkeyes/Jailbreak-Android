package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * 回退裁决（docs/99491-test-plan.md §3 D4 + Lead 最终流程）的纯逻辑验收。
 *
 * <p>核心不变量：只有"零内核写之前"的失败允许自动回退 98260；只要 direct 引擎已经 fire
 * （PARKED 记录 / `[+] cred`、`[+] fsuid`、`[+] caps`、SELinux 窗口、`[ko]`、`MODULE_LOADED` 等），
 * 或者出现 panic / 超时 / 无法归因的输出，就必须置 dirty 并要求重启。
 */
public class RootPathDecisionTest {

    private static final String PRE_WRITE =
            "[p] profile_ok release=6.18.21-android17-5-g805aa6adea19-abogki565292102-4k\n"
                    + "[p] anchor slide=0x10e7400000\n"
                    + "[p] engine=direct";

    /** 真实成功输出（含结尾"记得重启"的 PARKED 信息行）。 */
    private static final String SUCCESS_TAIL = PRE_WRITE + "\n"
            + "[!] direct engine: PARKED marker set for this boot; reboot before the next fire run\n"
            + "[+] cred cand=0xffffff80524f2c00 euid=0 (uaf_writes=1)\n"
            + "[+] fsuid=0\n"
            + "[+] caps bit16(CAP_SYS_MODULE)\n"
            + "[!] permissive window opened at selinux_state-1\n"
            + "[step] direct root: ko backend (patch ELF + finit_module)\n"
            + "[ko] patched=225 missing=0\n"
            + "[ko] finit_module result=0 errno=0 (ok)\n"
            + "[+] ko backend loaded (rc=0)\n"
            + "MODULE_LOADED\n"
            + "[f] module_live=1 enforce=1\n"
            + "su_check_begin\n"
            + "uid=0(root) context=u:r=ksu:s0\n"
            + "su_check_end";

    /** direct 引擎在 fire 前就失败：有 PARKED 记录但没有内核写证据。 */
    private static final String PARKED_PRE_FIRE = PRE_WRITE + "\n"
            + "[!] direct engine: PARKED marker set for this boot; reboot before the next fire run\n"
            + "[-] direct root: no euid-0 candidate\n"
            + "PARKED";

    @Test
    public void fullSuccessTailIsSuccess() {
        assertEquals(RootPathDecision.Decision.SUCCESS, RootPathDecision.decide(SUCCESS_TAIL));
        assertTrue(RootPathDecision.describe(RootPathDecision.Decision.SUCCESS).contains("接管"));
    }

    @Test
    public void preWriteFailureFallsBackTo98260() {
        assertEquals(RootPathDecision.Decision.FALLBACK_98260,
                RootPathDecision.decide(PRE_WRITE + "\n[!] anchor failed"));
        assertEquals(RootPathDecision.Decision.FALLBACK_98260,
                RootPathDecision.decide("[p] profile_ok release=x\n[p] precheck failed"));
        assertEquals(RootPathDecision.Decision.FALLBACK_98260,
                RootPathDecision.decide("PROFILE_MISMATCH release differs"));
        assertEquals(RootPathDecision.Decision.FALLBACK_98260,
                RootPathDecision.decide(PRE_WRITE + "\nleak failed"));
        // 旧 real_cred 契约的写前失败同样允许回退
        assertEquals(RootPathDecision.Decision.FALLBACK_98260,
                RootPathDecision.decide("[p] profile_ok release=x\n[!] anchor failed"));
    }

    @Test
    public void directEngineFireWithoutParkedIsDirty() {
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide(PRE_WRITE + "\n[+] cred cand=0x1 euid=0\n[-] direct root failed"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide(PRE_WRITE + "\n[+] fsuid=0\n[-] direct root failed"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide(PRE_WRITE + "\n[+] caps bit16(CAP_SYS_MODULE)\n[-] fail"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide(PRE_WRITE + "\n[!] permissive window opened at selinux_state-1"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide(PRE_WRITE + "\n[ko] finit_module result=1 errno=22"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide(PRE_WRITE + "\nMODULE_LOADED\n[-] su_check failed"));
    }

    @Test
    public void writeThenFailureIsDirtyBoot() {
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide("[+] swap uid=0\n[!] oracle miss"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide("[+] cred == real_cred\n[!] selinux restore failed"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide("[f] module_live=1 enforce=1\n[!] su_check failed"));
    }

    @Test
    public void parkedBeforeWriteIsParkedWithoutDirty() {
        assertEquals(RootPathDecision.Decision.PARKED, RootPathDecision.decide(PARKED_PRE_FIRE));
        assertTrue(RootPathDecision.describe(RootPathDecision.Decision.PARKED).contains("PARKED"));
    }

    @Test
    public void parkedAfterWriteIsStillDirty() {
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide("[+] swap uid=0\nPARKED"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide("[+] cred cand=0x1 euid=0\n[ko] finit_module failed\nPARKED"));
    }

    @Test
    public void abortAndPanicAreDirty() {
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT, RootPathDecision.decide("Kernel panic - not syncing"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide("[!] abort reason=holding zombie"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide(PRE_WRITE + "\nholding zombie"));
    }

    @Test
    public void timeoutIsDirtyEvenWithPreWriteEvidence() {
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide(PRE_WRITE, true));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide(PRE_WRITE, BootGuard.TIMEOUT_EXIT));
    }

    /** 超时前已经出现 PARKED 记录：按 PARKED 语义（本 boot 不再写）而不是无归因 dirty。 */
    @Test
    public void timeoutWithParkedRecordIsParked() {
        assertEquals(RootPathDecision.Decision.PARKED,
                RootPathDecision.decide(PARKED_PRE_FIRE + "\n[timeout]", true));
    }

    @Test
    public void noEvidenceIsFailClosedDirty() {
        assertEquals("空输出不能证明零写", RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide(""));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT, RootPathDecision.decide(null));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide("something odd happened", 1));
    }

    @Test
    public void preWriteEvidenceDetection() {
        assertTrue(RootPathDecision.hasPreWriteEvidence(PRE_WRITE));
        assertTrue(RootPathDecision.hasPreWriteEvidence("PROFILE_MISMATCH"));
        assertFalse(RootPathDecision.hasPreWriteEvidence("[+] swap uid=0"));
        assertFalse(RootPathDecision.hasPreWriteEvidence(""));
        assertFalse(RootPathDecision.hasPreWriteEvidence(null));
    }

    @Test
    public void decisionsHaveReadableDescriptions() {
        for (RootPathDecision.Decision decision : RootPathDecision.Decision.values()) {
            String text = RootPathDecision.describe(decision);
            assertFalse(decision.name(), text.isEmpty());
        }
    }
}
