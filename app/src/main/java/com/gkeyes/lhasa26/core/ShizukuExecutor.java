package com.gkeyes.lhasa26.core;

import rikka.shizuku.Shizuku;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Small, testable wrapper around the official Shizuku process API. */
public final class ShizukuExecutor implements CommandExecutor {
    public static final String WORK_DIR = "/data/local/tmp";
    private static final String[] ENV = {
            "PATH=/system/bin:/system/xbin",
            "HOME=/data/local/tmp",
            "TMPDIR=/data/local/tmp"
    };

    private static final Method NEW_PROCESS_METHOD = resolveNewProcessMethod();

    private static Method resolveNewProcessMethod() {
        try {
            Method method = Shizuku.class.getDeclaredMethod(
                    "newProcess", String[].class, String[].class, String.class);
            method.setAccessible(true);
            return method;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private final Set<Process> active =
            Collections.newSetFromMap(new ConcurrentHashMap<Process, Boolean>());

    /** 关闭后不再接受新的远端进程。 */
    private volatile boolean closed;

    @Override
    public boolean isAvailable() {
        try {
            return !closed && Shizuku.pingBinder() && Shizuku.checkSelfPermission() == 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    @Override
    public Process open(String command) throws Exception {
        if (closed) {
            throw new IllegalStateException("执行器已关闭");
        }
        if (!isAvailable()) {
            throw new IllegalStateException("Shizuku 未运行或尚未授权");
        }
        Process process = newProcess(new String[]{"sh", "-c", command}, ENV, WORK_DIR);
        if (process == null) {
            throw new IllegalStateException("Shizuku 拒绝启动 shell 进程");
        }
        active.add(process);
        return process;
    }

    @Override
    public void release(Process process) {
        if (process != null) {
            active.remove(process);
        }
    }

    @Override
    public void kill() {
        closed = true;
        List<Process> snapshot = new ArrayList<>(active);
        active.clear();
        for (Process process : snapshot) {
            destroy(process);
        }
    }

    private static void destroy(Process process) {
        if (process == null) {
            return;
        }
        try {
            process.destroy();
        } catch (Throwable ignored) {
            // The remote process may already be gone.
        }
        try {
            process.destroyForcibly();
        } catch (Throwable ignored) {
            // Nothing else to do.
        }
    }

    private static Process newProcess(String[] command, String[] environment, String directory) throws Exception {
        Method method = NEW_PROCESS_METHOD;
        if (method == null) {
            method = Shizuku.class.getDeclaredMethod(
                    "newProcess", String[].class, String[].class, String.class);
            method.setAccessible(true);
        }
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
        try {
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            Future<?> outFuture = drainAsync(process.getInputStream(), stdout);
            Future<?> errFuture = drainAsync(process.getErrorStream(), stderr);
            int exitCode;
            try {
                exitCode = CommandExecutor.waitWithTimeout(process, 120L);
            } catch (InterruptedException interrupted) {
                // 被中断时先真正杀掉进程，再让 finally 注销；否则它会脱离 active 集合继续跑。
                destroy(process);
                awaitQuietly(outFuture, 1000L);
                awaitQuietly(errFuture, 1000L);
                Thread.currentThread().interrupt();
                throw interrupted;
            }
            if (exitCode == CommandExecutor.TIMEOUT) {
                destroy(process);
                awaitQuietly(outFuture, 2000L);
                awaitQuietly(errFuture, 2000L);
                return new CommandResult(-1, "命令超时（120 秒）：" + command);
            }
            awaitQuietly(outFuture, 8000L);
            awaitQuietly(errFuture, 8000L);
            String out = stdout.toString(StandardCharsets.UTF_8.name());
            String err = stderr.toString(StandardCharsets.UTF_8.name());
            String combined = err.isEmpty() ? out : out + (out.isEmpty() ? "" : "\n") + err;
            if (!quiet && exitCode != 0 && combined.trim().isEmpty()) {
                combined = "命令退出码 " + exitCode;
            }
            return new CommandResult(exitCode, combined);
        } finally {
            active.remove(process);
        }
    }

    private static Future<?> drainAsync(InputStream input, ByteArrayOutputStream target) {
        return CommandExecutor.ASYNC_POOL.submit(() -> {
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
        });
    }

    private static void awaitQuietly(Future<?> future, long timeoutMs) {
        try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
            // Stream drain timeout should not mask the process result.
        }
    }
}
