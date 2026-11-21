package com.gkeyes.lhasa26.core;

import java.io.IOException;

public interface CommandExecutor {
    CommandResult run(String command, boolean quiet) throws Exception;

    Process open(String command) throws Exception;

    boolean isAvailable();

    /** Stops whatever remote process is currently running, if any. */
    default void kill() {
    }

    static String readProcessOutput(Process process) throws IOException, InterruptedException {
        StringBuilder output = new StringBuilder();
        Thread stdout = new Thread(() -> drain(process.getInputStream(), output), "lhasa-stdout");
        Thread stderr = new Thread(() -> drain(process.getErrorStream(), output), "lhasa-stderr");
        stdout.start();
        stderr.start();
        int exitCode;
        if (!process.waitFor(120L, java.util.concurrent.TimeUnit.SECONDS)) {
            process.destroy();
            if (!process.waitFor(5L, java.util.concurrent.TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
            joinQuietly(stdout);
            joinQuietly(stderr);
            output.append("命令超时（120 秒）");
            return output.toString();
        }
        exitCode = process.exitValue();
        joinQuietly(stdout);
        joinQuietly(stderr);
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
