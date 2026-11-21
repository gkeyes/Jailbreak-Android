package com.gkeyes.lhasa26.core;

import rikka.shizuku.Shizuku;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/** Small, testable wrapper around the official Shizuku process API. */
public final class ShizukuExecutor implements CommandExecutor {
    public static final String WORK_DIR = "/data/local/tmp";
    private static final String[] ENV = {
            "PATH=/system/bin:/system/xbin",
            "HOME=/data/local/tmp",
            "TMPDIR=/data/local/tmp"
    };
    private volatile Process active;

    @Override
    public boolean isAvailable() {
        try {
            return Shizuku.pingBinder() && Shizuku.checkSelfPermission() == 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    @Override
    public Process open(String command) throws Exception {
        if (!isAvailable()) {
            throw new IllegalStateException("Shizuku 未运行或尚未授权");
        }
        Process process = newProcess(new String[]{"sh", "-c", command}, ENV, WORK_DIR);
        if (process == null) {
            throw new IllegalStateException("Shizuku 拒绝启动 shell 进程");
        }
        active = process;
        return process;
    }

    @Override
    public void kill() {
        Process current = active;
        active = null;
        if (current == null) {
            return;
        }
        try {
            current.destroy();
        } catch (Throwable ignored) {
            // The remote process may already be gone.
        }
        try {
            current.destroyForcibly();
        } catch (Throwable ignored) {
            // Nothing else to do.
        }
    }

    /**
     * API 13.1.5 keeps newProcess private while the transition to UserService is in progress.
     * Keep the compatibility bridge isolated here so the rest of the app does not depend on
     * Shizuku internals. The public UserService migration can replace this adapter later.
     */
    private static Process newProcess(String[] command, String[] environment, String directory) throws Exception {
        Method method = Shizuku.class.getDeclaredMethod(
                "newProcess", String[].class, String[].class, String.class);
        method.setAccessible(true);
        try {
            return (Process) method.invoke(null, command, environment, directory);
        } catch (InvocationTargetException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw failure;
        }
    }

    @Override
    public CommandResult run(String command, boolean quiet) throws Exception {
        Process process = open(command);
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        Thread outThread = drainAsync(process.getInputStream(), stdout);
        Thread errThread = drainAsync(process.getErrorStream(), stderr);
        int exitCode = CommandExecutor.waitWithTimeout(process, 120L);
        if (exitCode == CommandExecutor.TIMEOUT) {
            kill();
            outThread.join(2000L);
            errThread.join(2000L);
            return new CommandResult(-1, "命令超时（120 秒）：" + command);
        }
        outThread.join(8000L);
        errThread.join(8000L);
        String out = stdout.toString(StandardCharsets.UTF_8.name());
        String err = stderr.toString(StandardCharsets.UTF_8.name());
        String combined = err.isEmpty() ? out : out + (out.isEmpty() ? "" : "\n") + err;
        if (!quiet && exitCode != 0 && combined.trim().isEmpty()) {
            combined = "命令退出码 " + exitCode;
        }
        active = null;
        return new CommandResult(exitCode, combined);
    }

    private static Thread drainAsync(InputStream input, ByteArrayOutputStream target) {
        Thread thread = new Thread(() -> {
            try (InputStream stream = input) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = stream.read(buffer)) >= 0) {
                    if (count > 0) {
                        target.write(buffer, 0, count);
                    }
                }
            } catch (Exception ignored) {
                // The command result is still useful when a stream closes during teardown.
            }
        }, "lhasa-shizuku-drain");
        thread.start();
        return thread;
    }
}
