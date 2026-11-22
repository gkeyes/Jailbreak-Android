package com.gkeyes.lhasa26.core;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public interface CommandExecutor {
    CommandResult run(String command, boolean quiet) throws Exception;

    Process open(String command) throws Exception;

    boolean isAvailable();

    /** Returned by waitWithTimeout when the bounded wait expired. */
    int TIMEOUT = Integer.MIN_VALUE;

    /**
     * 共享守护线程池。
     *
     * 之前每次 run() 都新建 3 个线程（等待 + 两条流 drain），一轮完整流程会产生上千个线程，
     * 在 UAF 堆布局敏感的窗口里制造调度噪声。
     */
    ExecutorService ASYNC_POOL = Executors.newCachedThreadPool(r -> {
        Thread thread = new Thread(r, "lhasa-exec");
        thread.setDaemon(true);
        return thread;
    });

    /** Stops whatever remote process is currently running, if any. */
    default void kill() {
    }

    /** 调用方用完某个 open() 出来的进程后注销它，避免集合里长期残留。 */
    default void release(Process process) {
    }

    /**
     * Waits for a Shizuku-backed process without calling exitValue(). The remote implementation keeps
     * its own exited flag, so the default waitFor(long, TimeUnit) reports completion early and the
     * timeout would never fire; a plain waitFor() on a worker thread is the only reliable option.
     */
    static int waitWithTimeout(Process process, long seconds) throws InterruptedException {
        final FutureTask<Integer> task = new FutureTask<>(() -> process.waitFor());
        ASYNC_POOL.execute(task);
        try {
            return task.get(seconds, TimeUnit.SECONDS);
        } catch (TimeoutException timeout) {
            task.cancel(true);
            try {
                process.destroy();
                process.destroyForcibly();
            } catch (Throwable ignored) {
                // Nothing else to do for a stuck remote process.
            }
            return TIMEOUT;
        } catch (java.util.concurrent.ExecutionException failure) {
            return -1;
        }
    }

    static String readProcessOutput(Process process) throws IOException, InterruptedException {
        StringBuilder output = new StringBuilder();
        Future<?> stdout = ASYNC_POOL.submit(() -> drain(process.getInputStream(), output));
        Future<?> stderr = ASYNC_POOL.submit(() -> drain(process.getErrorStream(), output));
        int exitCode = waitWithTimeout(process, 120L);
        awaitFuture(stdout);
        awaitFuture(stderr);
        if (exitCode == TIMEOUT) {
            throw new IOException("命令超时（120 秒）");
        }
        synchronized (output) {
            return output.toString();
        }
    }

    static void drain(java.io.InputStream stream, StringBuilder sink) {
        try (java.io.InputStream input = stream) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    synchronized (sink) {
                        sink.append(new String(buffer, 0, count));
                    }
                }
            }
        } catch (Exception ignored) {
            // The command result is still useful when a stream closes during teardown.
        }
    }

    static void awaitFuture(Future<?> future) {
        try {
            future.get(8000L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
            // Best-effort drain completion.
        }
    }
}
