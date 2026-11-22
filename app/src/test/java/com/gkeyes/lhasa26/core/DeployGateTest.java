package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

/**
 * Acceptance for the staging gate, driven through simulated staging tasks only.
 *
 * The three cases the flow must survive without ever announcing 程序已就位:
 *   timeout, cancellation, and a worker that succeeds after the deadline.
 */
public class DeployGateTest {

    private static Thread staging(AtomicReference<Exception> error, long sleepMs, Runnable body) {
        Thread worker = new Thread(() -> {
            try {
                if (body != null) {
                    body.run();
                }
                Thread.sleep(sleepMs);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                error.set(interrupted);
            } catch (Exception failure) {
                error.set(failure);
            }
        }, "staging-sim");
        worker.setDaemon(true);
        worker.start();
        return worker;
    }

    @Test
    public void completesBeforeDeadlineIsReady() throws Exception {
        AtomicReference<Exception> error = new AtomicReference<>();
        Thread worker = staging(error, 10L, null);

        DeployGate gate = new DeployGate(2000L);
        assertEquals(DeployGate.Result.READY, gate.await(worker, error));
        assertTrue(gate.isReady());
    }

    @Test
    public void timeoutIsNotReadyAndTerminatesTheFlow() throws Exception {
        AtomicReference<Exception> error = new AtomicReference<>();
        Thread worker = staging(error, 5000L, null);

        DeployGate gate = new DeployGate(120L);
        assertEquals(DeployGate.Result.TIMEOUT, gate.await(worker, error));
        assertFalse("超时后不得显示程序已就位", gate.isReady());
    }

    @Test
    public void cancelledTaskIsReportedAsCancelled() throws Exception {
        AtomicReference<Exception> error = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            try {
                Thread.sleep(5000L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                error.set(interrupted);
            }
        }, "staging-cancel");
        worker.setDaemon(true);
        worker.start();

        DeployGate gate = new DeployGate(100L);
        assertEquals(DeployGate.Result.TIMEOUT, gate.await(worker, error));
        assertFalse(gate.isReady());
    }

    @Test
    public void lateSuccessCannotFlipTheOutcome() throws Exception {
        AtomicReference<Exception> error = new AtomicReference<>();
        Thread worker = staging(error, 400L, null);

        DeployGate gate = new DeployGate(80L);
        assertEquals(DeployGate.Result.TIMEOUT, gate.await(worker, error));

        // Let the worker finish successfully after the gate already settled.
        worker.join(2000L);
        assertFalse("迟到成功不得改变结果", worker.isAlive());
        assertEquals(DeployGate.Result.TIMEOUT, gate.outcome());
        assertFalse(gate.isReady());
    }

    @Test
    public void failureIsReportedAsFailed() throws Exception {
        AtomicReference<Exception> error = new AtomicReference<>();
        Thread worker = staging(error, 0L, () -> error.set(new IllegalStateException("写入失败")));

        DeployGate gate = new DeployGate(2000L);
        assertEquals(DeployGate.Result.FAILED, gate.await(worker, error));
        assertFalse(gate.isReady());
    }

    @Test
    public void pendingGateHasNoOutcome() {
        DeployGate gate = new DeployGate(1000L);
        assertNull(gate.outcome());
        assertFalse(gate.isReady());
    }
}
