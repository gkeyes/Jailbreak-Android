package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Acceptance for the staging gate, driven through simulated staging tasks.
 *
 * A task is READY only when it explicitly reports completion. Everything else - an Error that escapes,
 * a task that simply returns, a task that ignores interrupts - must stay not-ready and must say
 * whether the worker is still alive.
 */
public class DeployGateTest {

    /** Starts a task that behaves like the real staging worker. */
    private static Thread task(DeployGate gate, long sleepMs, boolean complete, Runnable extra) {
        Thread worker = new Thread(() -> {
            try {
                if (extra != null) {
                    extra.run();
                }
                if (sleepMs > 0) {
                    Thread.sleep(sleepMs);
                }
                if (complete) {
                    gate.markCompleted();
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                gate.fail(interrupted);
            }
        }, "staging-sim");
        worker.setDaemon(true);
        worker.start();
        return worker;
    }

    @Test
    public void explicitCompletionIsReady() throws Exception {
        DeployGate gate = new DeployGate(2000L);
        Thread worker = task(gate, 10L, true, null);

        assertEquals(DeployGate.Result.READY, gate.await(worker));
        assertTrue(gate.isReady());
        assertFalse(gate.isWorkerAlive());
    }

    @Test
    public void errorThatEscapesIsNotReady() throws Exception {
        DeployGate gate = new DeployGate(2000L);
        Thread worker = task(gate, 0L, false, () -> {
            throw new AssertionError("模拟: 拷贝途中断言失败");
        });

        assertEquals(DeployGate.Result.FAILED, gate.await(worker));
        assertFalse("Error 跳过 catch 时不得视为就绪", gate.isReady());
    }

    @Test
    public void threadThatEndsWithoutReportingIsNotReady() throws Exception {
        DeployGate gate = new DeployGate(2000L);
        Thread worker = task(gate, 5L, false, null);

        assertEquals(DeployGate.Result.FAILED, gate.await(worker));
        assertFalse(gate.isReady());
    }

    @Test
    public void timeoutReportsWorkerIsGone() throws Exception {
        DeployGate gate = new DeployGate(120L);
        Thread worker = task(gate, 5000L, false, null);

        assertEquals(DeployGate.Result.TIMEOUT, gate.await(worker));
        assertFalse(gate.isReady());
        assertFalse("收到中断后应及时退出", gate.isWorkerAlive());
    }

    @Test
    public void workerIgnoringInterruptIsStuckAndSaysSo() throws Exception {
        DeployGate gate = new DeployGate(80L);
        Thread worker = new Thread(() -> {
            long until = System.currentTimeMillis() + 1500L;
            boolean interrupted = false;
            while (System.currentTimeMillis() < until) {
                try {
                    Thread.sleep(20L);
                } catch (InterruptedException ignored) {
                    interrupted = true;
                    // Deliberately keep running: this models a write that cannot be interrupted.
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }, "staging-stuck");
        worker.setDaemon(true);
        worker.start();

        assertEquals(DeployGate.Result.STUCK, gate.await(worker));
        assertFalse(gate.isReady());
        assertTrue("必须能说出后台写入还活着", gate.isWorkerAlive());
        worker.join(2000L);
    }

    @Test
    public void failureReportedByTaskIsFailed() throws Exception {
        DeployGate gate = new DeployGate(2000L);
        Thread worker = task(gate, 0L, false, () -> gate.fail(new IllegalStateException("写入失败")));

        assertEquals(DeployGate.Result.FAILED, gate.await(worker));
        assertFalse(gate.isReady());
    }

    @Test
    public void lateCompletionIsRejected() throws Exception {
        DeployGate gate = new DeployGate(80L);
        Thread worker = task(gate, 400L, true, null);

        assertEquals(DeployGate.Result.TIMEOUT, gate.await(worker));
        worker.join(2000L);
        assertEquals(DeployGate.Result.TIMEOUT, gate.outcome());
        assertFalse(gate.isReady());
    }

    @Test
    public void pendingGateHasNoOutcome() {
        DeployGate gate = new DeployGate(1000L);
        assertNull(gate.outcome());
        assertFalse(gate.isReady());
    }
}
