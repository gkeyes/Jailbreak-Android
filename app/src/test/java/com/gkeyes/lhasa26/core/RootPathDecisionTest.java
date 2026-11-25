package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * 回退裁决（docs/99491-test-plan.md §3 D4）的纯逻辑验收。
 *
 * <p>核心不变量：只有"零内核写之前"的失败允许自动回退 98260；只要出现过
 * `[+] swap/cred/setcon`、`MODULE_LOADED`、`[f] module_live`、`[f] su_check` 之一，
 * 或者出现 panic / timeout / 无法归因的输出，就必须置 dirty 并要求重启。
 */
public class RootPathDecisionTest {

    private static final String PRE_WRITE = "[p] profile_ok release=6.18.21-android17-5-g805aa6adea19-abogki565292102-4k\n"
            + "[p] anchor slide=0x10e7400000";

    @Test
    public void fullSuccessTailIsSuccess() {
        String tail = PRE_WRITE + "\n"
                + "[+] swap uid=0\n"
                + "[+] cred == real_cred\n"
                + "[+] setcon\n"
                + "MODULE_LOADED\n"
                + "[f] module_live=1 enforce=1\n"
                + "[f] su_check=uid=0 context=u:r=ksu:s0\n"
                + "[f] getenforce=Enforcing";
        assertEquals(RootPathDecision.Decision.SUCCESS, RootPathDecision.decide(tail));
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
    }

    @Test
    public void writeThenFailureIsDirtyBoot() {
        String swapTail = PRE_WRITE + "\n[+] swap uid=0\n[!] oracle miss";
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT, RootPathDecision.decide(swapTail));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide("[+] cred == real_cred\n[!] selinux restore failed"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide("MODULE_LOADED\n[!] ksud late-load failed"));
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide("[f] module_live=1 enforce=1\n[!] su_check failed"));
    }

    @Test
    public void parkedBeforeWriteIsParkedWithoutDirty() {
        String tail = PRE_WRITE + "\nPARKED reason=oracle miss";
        assertEquals(RootPathDecision.Decision.PARKED, RootPathDecision.decide(tail));
        assertTrue(RootPathDecision.describe(RootPathDecision.Decision.PARKED).contains("PARKED"));
    }

    @Test
    public void parkedAfterWriteIsStillDirty() {
        assertEquals(RootPathDecision.Decision.DIRTY_BOOT,
                RootPathDecision.decide("[+] swap uid=0\nPARKED reason=selinux window"));
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
                RootPathDecision.decide(PRE_WRITE, BootGuard.TIMEOUT_EXIT));
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
