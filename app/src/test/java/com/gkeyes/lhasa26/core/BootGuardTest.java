package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Acceptance for the payload marker classification and the kernel warning path.
 *
 * These are the exact strings the vendored payload emits; see plant/analysis-report.md.
 */
public class BootGuardTest {

    @Test
    public void plantedNodeAbortsTheBoot() {
        assertEquals(BootGuard.Outcome.ABORT_BOOT,
                BootGuard.classify("[uaf] missed page; holding zombie"));
    }

    @Test
    public void leakFailureIsSafeToRetry() {
        assertEquals(BootGuard.Outcome.RETRY_SAFE, BootGuard.classify("[task] leak failed"));
    }

    @Test
    public void credHitIsSuccess() {
        assertEquals(BootGuard.Outcome.SUCCESS, BootGuard.classify("[child-cred] uid=0"));
    }

    @Test
    public void intermediateStatesAreNotSuccess() {
        assertEquals(BootGuard.Outcome.CONTINUE, BootGuard.classify("[cred] child=7 holding pages"));
        assertEquals(BootGuard.Outcome.CONTINUE, BootGuard.classify("[selinux] already permissive"));
    }

    @Test
    public void abortWinsOverSuccessInTheSameTail() {
        String tail = "[uaf] missed page; holding zombie\n[child-cred] uid=0";
        assertEquals(BootGuard.Outcome.ABORT_BOOT, BootGuard.classify(tail));
    }

    @Test
    public void unknownKernelOnlyWarns() {
        String kernel = "6.18.21-android17-5-gdeadbeef-abogki1-4k";
        assertFalse(BootGuard.isSupportedKernel(kernel));
        assertTrue(BootGuard.kernelWarning(kernel).contains(kernel));
        assertTrue(BootGuard.kernelWarning(kernel).contains("继续尝试"));
    }

    @Test
    public void supportedKernelIsRecognised() {
        assertTrue(BootGuard.isSupportedKernel(
                "6.18.21-android17-5-g284297031c53-abogki553682993-4k"));
    }

    @Test
    public void launchAndKillUseProcessGroupSemantics() {
        assertTrue(BootGuard.launchCommand("/data/local/tmp/uaf_plant_replay", "--slide 0x1", "/tmp/log")
                .contains("toybox setsid"));
        assertTrue(BootGuard.killCommand().contains("kill -TERM -$p"));
        assertTrue(BootGuard.aliveCommand().contains("kill -0 -$p"));
    }
}
