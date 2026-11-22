package com.gkeyes.lhasa26.core;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Deployment gate: a step may only be announced as ready when the staging task actually finished.
 *
 * The previous code did {@code deploy.join(8000L)} and then only checked whether an exception had been
 * recorded. A task that was still copying 5 MB through the Shizuku pipe passed that check, the flow
 * announced 程序已就位, and the exploit then raced the still-running copy for I/O and memory.
 *
 * This gate settles exactly once. A late success after the timeout cannot turn the outcome back to
 * READY, because READY is only produced on the path where the worker was already dead and no error
 * was recorded.
 */
public final class DeployGate {

    /** Terminal outcome of one staging attempt. */
    public enum Result {
        READY,
        TIMEOUT,
        CANCELLED,
        FAILED
    }

    private final long timeoutMs;
    private volatile Result outcome;

    public DeployGate(long timeoutMs) {
        this.timeoutMs = timeoutMs > 0 ? timeoutMs : 8000L;
    }

    /**
     * Waits for the staging task and settles the outcome.
     *
     * A task that is still alive at the deadline is interrupted and reported as TIMEOUT. A task that
     * fails with InterruptedException is reported as CANCELLED, so the two cases stay distinguishable
     * in the log.
     */
    public Result await(Thread worker, AtomicReference<Exception> error) throws InterruptedException {
        synchronized (this) {
            if (outcome != null) {
                return outcome;
            }
        }

        long deadline = System.currentTimeMillis() + timeoutMs;
        while (worker.isAlive()) {
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0L) {
                worker.interrupt();
                worker.join(500L);
                // The outcome is fixed here. If the worker completes successfully after this point it
                // must not be able to rewrite it, which is why READY is never set on this path.
                return settle(Result.TIMEOUT);
            }
            worker.join(Math.min(remaining, 100L));
        }

        Exception failure = error == null ? null : error.get();
        if (failure == null) {
            return settle(Result.READY);
        }
        if (failure instanceof InterruptedException
                || (failure.getCause() instanceof InterruptedException)) {
            return settle(Result.CANCELLED);
        }
        return settle(Result.FAILED);
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

    /** True only when staging provably completed before the deadline. */
    public boolean isReady() {
        return outcome() == Result.READY;
    }
}
