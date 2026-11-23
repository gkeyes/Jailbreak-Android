package com.gkeyes.lhasa26.core;

import android.content.res.AssetManager;

import java.io.InputStream;
import java.io.OutputStream;

/** Copies the supplied device-specific payloads through the already-authorized shell. */
public final class AssetDeployer {
    /**
     * Payloads needed before the exploit runs.
     *
     * `ksud` is deliberately absent: it is 4.9 MB, only used by the KernelSU step (staged on demand
     * after root is established), and pulling it through the Shizuku pipe inside the pre-exploit
     * window costs both time and heap churn.
     *
     * `perf_slide` was removed on 2026-11-22: this ROM's SELinux denies `{ kernel }` on
     * `tclass=perf_event` for `u:r:shell:s0`, so perf kernel sampling can never succeed here.
     *
     * `reach_probe` is only needed by diagnosis (staged on demand there), and `lhasa_profile.txt`
     * is compiled into the upstream binaries by tools/gen_xr_profiles.py.
     */
    public static final String[] RUNTIME_ASSETS = {
            "slide_probe", "uaf_plant_replay", "pc98260-su"
    };

    private final AssetManager assets;
    private final CommandExecutor executor;
    private final WorkflowLog log;

    /** 正在写入的远端进程；取消时靠它把阻塞中的 cat 打断。 */
    private volatile Process inFlight;
    /** 部署被取消后，stageAll 不再继续下一项（否则会在清理之后把文件又写回去）。 */
    private volatile boolean cancelled;

    public AssetDeployer(AssetManager assets, CommandExecutor executor, WorkflowLog log) {
        this.assets = assets;
        this.executor = executor;
        this.log = log;
    }

    /**
     * 取消进行中的部署。
     *
     * 负责销毁当前写入进程并把标志置位；调用方仍需 join 部署线程确认它真的退出了。
     */
    public void cancel() {
        cancelled = true;
        Process current = inFlight;
        inFlight = null;
        if (current != null) {
            try {
                current.destroyForcibly();
            } catch (Throwable ignored) {
                // Best effort only.
            }
        }
    }

    public boolean isCancelled() {
        return cancelled;
    }

    public void stageAll() throws Exception {
        cancelled = false;
        for (String asset : RUNTIME_ASSETS) {
            if (cancelled) {
                throw new IllegalStateException("部署已被取消，停止后续写入");
            }
            stage(asset);
        }
    }

    public void stage(String assetName) throws Exception {
        if (cancelled) {
            throw new IllegalStateException("部署已被取消，跳过 " + assetName);
        }
        String destination = ShizukuExecutor.WORK_DIR + "/" + assetName;
        log.append("部署 " + destination);
        Process process = executor.open("cat > '" + destination + ".new'"
                + " && chmod 755 '" + destination + ".new'"
                + " && mv -f '" + destination + ".new' '" + destination + "'");
        inFlight = process;
        boolean finished = false;
        try {
            try (InputStream input = assets.open(assetName);
                 OutputStream output = process.getOutputStream()) {
                byte[] buffer = new byte[65536];
                int count;
                while ((count = input.read(buffer)) >= 0) {
                    if (cancelled) {
                        throw new IllegalStateException("部署被取消：" + assetName);
                    }
                    if (count > 0) {
                        output.write(buffer, 0, count);
                    }
                }
            }
            String output = CommandExecutor.readProcessOutput(process);
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IllegalStateException("写入 " + assetName + " 失败：" + output);
            }
            finished = true;
        } finally {
            if (!finished) {
                try {
                    process.destroyForcibly();
                } catch (Throwable ignored) {
                    // Best effort only.
                }
            }
            if (inFlight == process) {
                inFlight = null;
            }
            executor.release(process);
        }
    }

    public interface WorkflowLog {
        void append(String line);
    }
}
