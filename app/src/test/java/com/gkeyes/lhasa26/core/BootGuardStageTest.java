package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * 阶段面包屑与硬超时都是纯字符串逻辑，可以在 JVM 上直接测。
 * 这两样存在的理由只有一个：设备被重启后，下一次启动能说清"上次停在哪"。
 */
public class BootGuardStageTest {

    @Test
    public void withTimeoutWrapsCommand() {
        assertEquals("timeout 8 /data/local/tmp/perf_slide --duration 1",
                BootGuard.withTimeout(8, "/data/local/tmp/perf_slide --duration 1"));
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

        String perf = BootGuard.leftoverStageHint("probe-perf 1763803200000");
        assertTrue(perf, perf.contains("perf_slide"));
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
}
