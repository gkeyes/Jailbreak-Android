package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * ksud userspace 收尾（T2c）的纯逻辑验收。
 *
 * <p>真机 ROOT12：ko 后端加载模块后模块 Live、su 可用且 uid=0，但 SELinux context 仍是
 * kernel；需要补一次 `su -c '/data/adb/ksud late-load --allow-shell --kmi android17-6.18'`。
 * 验收规则：uid=0 + ksu → 正常成功；uid=0 + kernel（或其它非 shell/untrusted）→ 降级成功并标注；
 * uid≠0 / shell / untrusted → fail-closed。
 *
 * <p>命令执行通过 {@link KsuUserspaceFinisher.Runner} 注入，本测试不跑真实进程。
 */
public class KsuUserspaceFinisherTest {

    private static final String KSU =
            "uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0";
    private static final String KERNEL =
            "uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0";
    private static final String SHELL =
            "uid=2000(shell) gid=2000(shell) groups=2000(shell) context=u:r:shell:s0";
    private static final String UID0_SHELL =
            "uid=0(root) gid=0(root) groups=0(root) context=u:r:shell:s0";

    /** 可脚本化的 Runner：记录调用顺序、睡眠预算、收尾命令是否执行/失败。 */
    private static final class FakeRunner implements KsuUserspaceFinisher.Runner {
        final Deque<String> suOutputs = new ArrayDeque<>();
        final List<String> calls = new ArrayList<>();
        final List<Long> sleeps = new ArrayList<>();
        RuntimeException finishError;
        RuntimeException firstSuError;
        int suCalls;
        int finishCalls;

        FakeRunner(String... outputs) {
            for (String output : outputs) {
                suOutputs.add(output);
            }
        }

        @Override
        public String runSuId() throws Exception {
            suCalls++;
            calls.add("su");
            if (firstSuError != null && suCalls == 1) {
                throw firstSuError;
            }
            if (suOutputs.isEmpty()) {
                throw new IllegalStateException("没有 scripted su 输出");
            }
            return suOutputs.size() > 1 ? suOutputs.poll() : suOutputs.peek();
        }

        @Override
        public String runFinish() throws Exception {
            finishCalls++;
            calls.add("finish");
            if (finishError != null) {
                throw finishError;
            }
            return "";
        }

        @Override
        public void sleepMs(long millis) {
            calls.add("sleep");
            sleeps.add(millis);
        }
    }

    @Test
    public void commandInstallsKsudThenFinishesWithAllowShellAndExplicitKmi() {
        String command = KsuUserspaceFinisher.finishCommand();
        assertEquals("su -c '[ -x /data/adb/ksud ] || cp /data/local/tmp/ksud /data/adb/ksud;"
                + " chmod 755 /data/adb/ksud 2>/dev/null;"
                + " /data/adb/ksud late-load --allow-shell --kmi android17-6.18'", command);
        assertTrue("幂等：已存在则跳过 cp", command.contains("[ -x /data/adb/ksud ] || cp"));
        assertTrue(command, command.contains("cp /data/local/tmp/ksud /data/adb/ksud"));
        assertTrue(command, command.contains("chmod 755 /data/adb/ksud"));
        assertTrue(command, command.contains("late-load --allow-shell --kmi android17-6.18"));
        assertEquals("android17-6.18", KsuUserspaceFinisher.KMI);
        assertEquals("/data/adb/ksud", KsuUserspaceFinisher.KSUD_BIN);
        assertEquals("/data/local/tmp/ksud", KsuUserspaceFinisher.KSUD_SRC);
    }

    @Test
    public void moduleNotLiveSkipsTheFinisherEntirely() {
        FakeRunner runner = new FakeRunner();
        KsuUserspaceFinisher.Verdict verdict = KsuUserspaceFinisher.finishIfNeeded(false, runner);
        assertEquals(KsuUserspaceFinisher.Result.SKIPPED_NOT_LIVE, verdict.result);
        assertFalse(verdict.success);
        assertEquals(0, runner.suCalls);
        assertEquals(0, runner.finishCalls);
        assertTrue(runner.calls.isEmpty());
    }

    @Test
    public void alreadyKsuDoesNotRunTheFinishCommand() {
        FakeRunner runner = new FakeRunner(KSU);
        KsuUserspaceFinisher.Verdict verdict = KsuUserspaceFinisher.finishIfNeeded(true, runner);
        assertEquals(KsuUserspaceFinisher.Result.ALREADY_KSU, verdict.result);
        assertTrue(verdict.success);
        assertFalse(verdict.degraded);
        assertEquals(0, runner.finishCalls);
        assertEquals("context=u:r=ksu:s0", verdict.contextNote);
    }

    @Test
    public void kernelContextTriggersFinishAndThenKsuSucceeds() {
        FakeRunner runner = new FakeRunner(KERNEL, KERNEL, KSU);
        KsuUserspaceFinisher.Verdict verdict = KsuUserspaceFinisher.finishIfNeeded(true, runner);
        assertEquals(KsuUserspaceFinisher.Result.FINISHED_KSU, verdict.result);
        assertTrue(verdict.success);
        assertFalse(verdict.degraded);
        assertEquals(1, runner.finishCalls);
        assertTrue(verdict.finishAttempted);
        // 顺序：先读 su → 执行收尾 → 再读 su 复验
        assertTrue(runner.calls.indexOf("finish") > 0);
        assertTrue(runner.calls.lastIndexOf("su") > runner.calls.indexOf("finish"));
        assertEquals("ksu", verdict.contextDomain);
    }

    @Test
    public void kernelContextAfterFinishIsDegradedSuccessWithNote() {
        FakeRunner runner = new FakeRunner(KERNEL);
        KsuUserspaceFinisher.Verdict verdict = KsuUserspaceFinisher.finishIfNeeded(true, runner);
        assertEquals(KsuUserspaceFinisher.Result.FINISHED_DEGRADED, verdict.result);
        assertTrue("uid=0 + kernel context 必须判成功（降级）", verdict.success);
        assertTrue(verdict.degraded);
        assertEquals(1, runner.finishCalls);
        assertTrue(verdict.detail, verdict.detail.contains("降级"));
        assertTrue(verdict.contextNote, verdict.contextNote.contains("context=kernel"));
        assertTrue(verdict.contextNote, verdict.contextNote.contains("降级"));
    }

    @Test
    public void finishCommandFailureDoesNotUndoAnAlreadyUsableSu() {
        FakeRunner runner = new FakeRunner(KERNEL);
        runner.finishError = new IllegalStateException("late-load 失败");
        KsuUserspaceFinisher.Verdict verdict = KsuUserspaceFinisher.finishIfNeeded(true, runner);
        assertEquals(KsuUserspaceFinisher.Result.FINISHED_DEGRADED, verdict.result);
        assertTrue(verdict.success);
        assertTrue(verdict.finishError, verdict.finishError.contains("late-load"));
    }

    @Test
    public void uidNotZeroFailsClosed() {
        FakeRunner runner = new FakeRunner(SHELL);
        KsuUserspaceFinisher.Verdict verdict = KsuUserspaceFinisher.finishIfNeeded(true, runner);
        assertEquals(KsuUserspaceFinisher.Result.FAILED, verdict.result);
        assertFalse(verdict.success);
        assertEquals(1, runner.finishCalls);
        assertTrue(verdict.detail, verdict.detail.contains("uid="));
    }

    @Test
    public void uidZeroButShellContextFailsClosed() {
        FakeRunner runner = new FakeRunner(UID0_SHELL);
        KsuUserspaceFinisher.Verdict verdict = KsuUserspaceFinisher.finishIfNeeded(true, runner);
        assertEquals(KsuUserspaceFinisher.Result.FAILED, verdict.result);
        assertFalse(verdict.success);
        assertEquals("shell", verdict.contextDomain);
        assertTrue(verdict.detail, verdict.detail.contains("shell"));
    }

    @Test
    public void unknownContextWithUidZeroIsDegradedNotFailed() {
        FakeRunner runner = new FakeRunner("uid=0(root) gid=0(root) groups=0(root)");
        KsuUserspaceFinisher.Verdict verdict = KsuUserspaceFinisher.finishIfNeeded(true, runner);
        assertEquals(KsuUserspaceFinisher.Result.FINISHED_DEGRADED, verdict.result);
        assertTrue(verdict.success);
        assertTrue(verdict.contextNote, verdict.contextNote.contains("未知"));
    }

    @Test
    public void waitBudgetIsBoundedToTenSeconds() {
        FakeRunner runner = new FakeRunner(KERNEL);
        KsuUserspaceFinisher.finishIfNeeded(true, runner);
        long total = 0L;
        for (Long sleep : runner.sleeps) {
            assertTrue(sleep <= KsuUserspaceFinisher.DEFAULT_POLL_MS);
            total += sleep;
        }
        assertEquals(KsuUserspaceFinisher.DEFAULT_WAIT_MS, total);
    }

    @Test
    public void initialSuReadFailureStillFinishesAndRecovers() {
        FakeRunner runner = new FakeRunner(KERNEL);
        runner.firstSuError = new IllegalStateException("su 暂时不可用");
        KsuUserspaceFinisher.Verdict verdict = KsuUserspaceFinisher.finishIfNeeded(true, runner);
        assertTrue("收尾命令仍需执行一次", verdict.finishAttempted);
        assertEquals(KsuUserspaceFinisher.Result.FINISHED_DEGRADED, verdict.result);
        assertTrue(verdict.success);
    }

    @Test
    public void contextAndUidParsing() {
        assertEquals("kernel", KsuUserspaceFinisher.parseContextDomain("context=u:r:kernel:s0"));
        assertEquals("ksu", KsuUserspaceFinisher.parseContextDomain("u:r:ksu:s0"));
        assertEquals("ksu", KsuUserspaceFinisher.parseContextDomain("u:r=ksu:s0"));
        assertEquals("kernel", KsuUserspaceFinisher.parseContextDomain("context=kernel"));
        assertEquals("kernel", KsuUserspaceFinisher.parseContextDomain("context=u:r:kernel:s0"));
        assertEquals("", KsuUserspaceFinisher.parseContextDomain(""));
        assertEquals("", KsuUserspaceFinisher.parseContextDomain(null));

        assertEquals(0L, KsuUserspaceFinisher.parseUid("uid=0(root) gid=0(root)"));
        assertEquals(2000L, KsuUserspaceFinisher.parseUid("uid=2000(shell)"));
        assertEquals(-1L, KsuUserspaceFinisher.parseUid("no uid here"));
        assertEquals(-1L, KsuUserspaceFinisher.parseUid(null));
    }

    @Test
    public void unsafeDomainsAreRejected() {
        assertTrue(KsuUserspaceFinisher.isUnsafeDomain("shell"));
        assertTrue(KsuUserspaceFinisher.isUnsafeDomain("untrusted_app"));
        assertFalse(KsuUserspaceFinisher.isUnsafeDomain("kernel"));
        assertFalse(KsuUserspaceFinisher.isUnsafeDomain("ksu"));
        assertFalse(KsuUserspaceFinisher.isUnsafeDomain(""));
    }
}
