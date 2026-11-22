package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * 阶段面包屑、硬超时、失败门禁都是纯字符串逻辑，可以在 JVM 上直接测。
 * 它们存在的理由只有一个：设备被重启后，下一次启动能说清"上次停在哪、还能不能再跑"。
 */
public class BootGuardStageTest {

    @Test
    public void withTimeoutWrapsCommandAndKillsHard() {
        assertEquals("timeout -k 2 8 /data/local/tmp/slide_probe",
                BootGuard.withTimeout(8, "/data/local/tmp/slide_probe"));
    }

    @Test
    public void timeoutExitIsTheUnixConvention() {
        assertEquals(124, BootGuard.TIMEOUT_EXIT);
    }

    @Test
    public void markCommandWritesStageFile() {
        String command = BootGuard.markCommand("payload");
        assertTrue(command, command.contains(BootGuard.STAGE_FILE));
        assertTrue(command, command.startsWith("echo 'payload "));
    }

    @Test
    public void markCommandSanitizesStage() {
        String command = BootGuard.markCommand("weird stage; rm -rf /");
        assertTrue(command, command.contains("weird_stage__rm_-rf__"));
    }

    @Test
    public void leftoverHintIsEmptyWithoutLeftover() {
        assertEquals("", BootGuard.leftoverStageHint(""));
        assertEquals("", BootGuard.leftoverStageHint(null));
        assertEquals("", BootGuard.leftoverStageHint("   "));
    }

    @Test
    public void leftoverHintNamesTheRiskyStage() {
        String payload = BootGuard.leftoverStageHint("payload 1763803200000");
        assertTrue(payload, payload.contains("主利用"));

        String ksu = BootGuard.leftoverStageHint("ksu 1763803200000");
        assertTrue(ksu, ksu.contains("KernelSU late-load"));
        assertTrue(ksu, ksu.contains("重启"));

        String slide = BootGuard.leftoverStageHint("probe-slide 1763803200000");
        assertTrue(slide, slide.contains("slide_probe"));
    }

    @Test
    public void unknownStageFallsBackToRawName() {
        assertTrue(BootGuard.leftoverStageHint("mystery 1").contains("mystery"));
    }

    @Test
    public void clearStageRemovesFile() {
        assertTrue(BootGuard.clearStageCommand().contains(BootGuard.STAGE_FILE));
        assertTrue(BootGuard.clearStageCommand().startsWith("rm -f "));
    }

    /** `[selinux] attempt 1/6` 出现在正常推进途中，绝不能当成重试信号。 */
    @Test
    public void selinuxAttemptIsNotARetrySignal() {
        assertEquals(BootGuard.Outcome.CONTINUE,
                BootGuard.classify("[selinux] attempt 1/6 target=0xffffffd780159629"));
        assertEquals(BootGuard.Outcome.CONTINUE,
                BootGuard.classify("[stream] writes=120 hit=1 seen=1"));
    }

    @Test
    public void leakFailureIsRetrySafe() {
        assertEquals(BootGuard.Outcome.RETRY_SAFE, BootGuard.classify("[uaf] leak failed"));
    }

    @Test
    public void holdingZombieAbortsTheBoot() {
        assertEquals(BootGuard.Outcome.ABORT_BOOT,
                BootGuard.classify("[uaf] holding zombie, not reaping"));
    }

    /** abort 记录一律禁止重跑，与 SELinux 是否 Permissive 无关。 */
    @Test
    public void abortBlocksRetryRegardlessOfPermissive() {
        assertEquals(BootGuard.Retry.BLOCKED,
                BootGuard.parseFailure("boot-1 abort", "boot-1"));
        assertEquals(BootGuard.Retry.BLOCKED,
                BootGuard.parseFailure("boot-1 enforcing", "boot-1"));
        assertEquals(BootGuard.Retry.PERMISSIVE_RETRY,
                BootGuard.parseFailure("boot-1 permissive", "boot-1"));
    }

    /** 旧格式 `<boot> 0|1` 仍要能解析。 */
    @Test
    public void legacyFailureFormatStillParses() {
        assertEquals(BootGuard.Retry.PERMISSIVE_RETRY, BootGuard.parseFailure("boot-1 0", "boot-1"));
        assertEquals(BootGuard.Retry.BLOCKED, BootGuard.parseFailure("boot-1 1", "boot-1"));
    }

    /** 上一次开机的记录与本次无关。 */
    @Test
    public void previousBootRecordIsIgnored() {
        assertEquals(BootGuard.Retry.ALLOWED, BootGuard.parseFailure("boot-old abort", "boot-new"));
        assertEquals(BootGuard.Retry.ALLOWED, BootGuard.parseFailure("", "boot-new"));
    }

    @Test
    public void recordFailureEncodesReason() {
        assertTrue(BootGuard.recordFailureCommand("b1", true, true).contains("abort"));
        assertTrue(BootGuard.recordFailureCommand("b1", false, true).contains("permissive"));
        assertTrue(BootGuard.recordFailureCommand("b1", false, false).contains("enforcing"));
        assertFalse(BootGuard.recordFailureCommand("", true, true).contains(BootGuard.FAILED_FILE));
    }
}
