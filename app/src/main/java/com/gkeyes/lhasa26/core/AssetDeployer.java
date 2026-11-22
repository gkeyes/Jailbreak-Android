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
     * KASLR slide now comes from `slide_probe` (tracefs binary-record scan).
     *
     * `reach_probe` is only needed by diagnosis (staged on demand there), and `lhasa_profile.txt`
     * is compiled into the upstream binaries by tools/gen_xr_profiles.py, so neither is deployed up
     * front any more — that saves ~47 KB and two pipe round-trips per run.
     */
    public static final String[] RUNTIME_ASSETS = {
            "slide_probe", "uaf_plant_replay", "pc98260-su"
    };

    private final AssetManager assets;
    private final CommandExecutor executor;
    private final WorkflowLog log;

    public AssetDeployer(AssetManager assets, CommandExecutor executor, WorkflowLog log) {
        this.assets = assets;
        this.executor = executor;
        this.log = log;
    }

    public void stageAll() throws Exception {
        for (String asset : RUNTIME_ASSETS) {
            stage(asset);
        }
    }

    public void stage(String assetName) throws Exception {
        String destination = ShizukuExecutor.WORK_DIR + "/" + assetName;
        log.append("部署 " + destination);
        Process process = executor.open("cat > '" + destination + ".new'"
                + " && chmod 755 '" + destination + ".new'"
                + " && mv -f '" + destination + ".new' '" + destination + "'");
        boolean finished = false;
        try {
            try (InputStream input = assets.open(assetName);
                 OutputStream output = process.getOutputStream()) {
                byte[] buffer = new byte[65536];
                int count;
                while ((count = input.read(buffer)) >= 0) {
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
            // 异常或超时路径上必须把远端 cat 进程收掉，否则它会和新一轮写入抢同一个文件。
            if (!finished) {
                try {
                    process.destroyForcibly();
                } catch (Throwable ignored) {
                    // Best effort only.
                }
            }
            executor.release(process);
        }
    }

    public interface WorkflowLog {
        void append(String line);
    }
}
