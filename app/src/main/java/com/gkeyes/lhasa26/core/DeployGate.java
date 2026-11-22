package com.gkeyes.lhasa26.core;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Deployment gate: staging is announced as ready only when the staging task says so.
 *
 * Two earlier shapes were wrong and are called out here because they are easy to regress into:
 *
 * 1. "No exception recorded and the thread is dead" is NOT success. An {@link Error} (assertion,
 *    linkage, OOM) escapes a {@code catch (Exception)} block, the thread dies, the error holder stays
 *    empty, and the gate used to return READY.
 * 2. A thread that ignores {@link Thread#interrupt()} keeps writing. Returning TIMEOUT without saying
 *    whether the worker is still alive hides that.
 *
 * READY therefore requires an explicit {@link #markCompleted()} from the task, and every non-ready
 * outcome carries {@link #isWorkerAlive()} so the caller has evidence about the background write.
 */
public final class DeployGate {

    /** Terminal outcome of one staging attempt. */
    public enum Result {
        /** The task reported completion and the worker is gone. */
        READY,
        /** The worker ended without reporting completion, or reported a failure. */
        FAILED,
        /** The deadline passed, the worker was interrupted and died. */
        TIMEOUT,
        /** The deadline passed and the worker ignored the interrupt; it may still be writing. */
        STUCK
    }

    private static final long ABORT_GRACE_MS = 500L;

    private final long timeoutMs;
    private final AtomicBoolean completed = new AtomicBoolean(false);
    private volatile Throwable failure;
    private volatile Result outcome;
    private volatile boolean workerAlive;

    public DeployGate(long timeoutMs) {
        this.timeoutMs = timeoutMs > 0 ? timeoutMs : 8000L;
    }

    /**
     * Called by the staging task as its last statement.
     *
     * Returns false when the gate already settled, which tells a late finisher that its work no longer
     * counts and it must not touch the device further.
     */
    public boolean markCompleted() {
        if (outcome != null && outcome != Result.READY) {
            return false;
        }
        return completed.compareAndSet(false, true);
    }

    /** Called by the staging task when it fails. Throwable, not Exception: Errors must count too. */
    public void fail(Throwable error) {
        failure = error;
    }

    /** Waits for the worker and settles exactly once. */
    public Result await(Thread worker) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;

        while (worker.isAlive()) {
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0L) {
                break;
            }
            worker.join(Math.min(remaining, 50L));
        }

        if (!worker.isAlive()) {
            workerAlive = false;
            if (failure != null) {
                return settle(Result.FAILED);
            }
            // Dead without an explicit completion: an Error escaped, or the task forgot to report.
            return settle(completed.get() ? Result.READY : Result.FAILED);
        }

        worker.interrupt();
        worker.join(ABORT_GRACE_MS);
        workerAlive = worker.isAlive();
        return settle(workerAlive ? Result.STUCK : Result.TIMEOUT);
    }

    private synchronized Result settle(Result result) {
        if (outcome == null) {
            outcome = result;
        }
        return outcome;
    }

    /** Current outcome, or null while still pending. */
    public Result outcome() {
        return outcome;
    }

    /** True only when the task explicitly reported completion. */
    public boolean isReady() {
        return outcome() == Result.READY;
    }

    /** Whether the staging worker was still alive when the gate settled. */
    public boolean isWorkerAlive() {
        return workerAlive;
    }
}
