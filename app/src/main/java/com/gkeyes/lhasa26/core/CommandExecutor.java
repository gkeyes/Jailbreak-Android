package com.gkeyes.lhasa26.core;

import java.io.IOException;

public interface CommandExecutor {
    CommandResult run(String command, boolean quiet) throws Exception;

    Process open(String command) throws Exception;

    boolean isAvailable();

    /** Returned by waitWithTimeout when the bounded wait expired. */
    int TIMEOUT = Integer.MIN_VALUE;

    /** Stops whatever remote process is currently running, if any. */
    default void kill() {
    }

    /**
     * Waits for a Shizuku-backed process without calling exitValue(). The remote implementation keeps
     * its own exited flag, so the default waitFor(long, TimeUnit) reports completion early and the
     * follow-up exitValue() throws "process hasn't exited".
     */
    static int waitWithTimeout(Process process, long seconds) throws InterruptedException {
        final java.util.concurrent.FutureTask<Integer> task =
                new java.util.concurrent.FutureTask<>(() -> process.waitFor());
        Thread thread = new Thread(task, "lhasa-wait");
        thread.setDaemon(true);
        thread.start();
        try {
            return task.get(seconds, java.util.concurrent.TimeUnit.SECONDS);
        } catch (java.util.concurrent.TimeoutException timeout) {
            task.cancel(true);
            try {
                process.destroy();
            } catch (Throwable ignored) {
                // Remote process may already be gone.
            }
            try {
                process.destroyForcibly();
            } catch (Throwable ignored) {
                // Nothing else to do.
            }
            return TIMEOUT;
        } catch (java.util.concurrent.ExecutionException failure) {
            return TIMEOUT;
        }
    }

    static String readProcessOutput(Process process) throws IOException, InterruptedException {
        StringBuilder output = new StringBuilder();
        Thread stdout = new Thread(() -> drain(process.getInputStream(), output), "lhasa-stdout");
        Thread stderr = new Thread(() -> drain(process.getErrorStream(), output), "lhasa-stderr");
        stdout.start();
        stderr.start();
        int exitCode = waitWithTimeout(process, 120L);
        joinQuietly(stdout);
        joinQuietly(stderr);
        if (exitCode == TIMEOUT) {
            throw new IOException("命令超时（120 秒）");
        }
        if (exitCode != 0 && output.length() == 0) {
            output.append("命令退出码 ").append(exitCode);
        }
        return output.toString();
    }

    static void drain(java.io.InputStream input, StringBuilder output) {
        try (java.io.InputStream stream = input) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = stream.read(buffer)) >= 0) {
                if (count > 0) {
                    synchronized (output) {
                        output.append(new String(buffer, 0, count, java.nio.charset.StandardCharsets.UTF_8));
                    }
                }
            }
        } catch (Exception ignored) {
            // The command result is still useful when a stream closes during process teardown.
        }
    }

    static void joinQuietly(Thread thread) {
        try {
            thread.join(8000L);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
