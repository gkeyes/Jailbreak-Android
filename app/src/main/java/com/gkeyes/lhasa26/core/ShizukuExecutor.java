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

    /** 反射查找一次即可；API 13.1.5 里 newProcess 还是私有方法。 */
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

    /**
     * 所有在跑的远端进程。
     *
     * 之前是单个 `volatile Process active`：部署线程（stageAll → open）和工作线程
     * （waitForIdle → run → 结尾 active = null）会互相覆盖，于是 DeployGate 超时时
     * kill() 拿不到真正卡住的那个进程，被覆盖的另一条还会泄漏。
     */
    private final Set<Process> active =
            Collections.newSetFromMap(new ConcurrentHashMap<Process, Boolean>());

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

    /**
     * API 13.1.5 keeps newProcess private while the transition to UserService is in progress.
     * Keep the compatibility bridge isolated here so the rest of the app does not depend on
     * Shizuku internals.
     */
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
            int exitCode = CommandExecutor.waitWithTimeout(process, 120L);
            if (exitCode == CommandExecutor.TIMEOUT) {
                // 只销毁这一次调用的进程，不要把部署线程里的进程一起带走。
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
