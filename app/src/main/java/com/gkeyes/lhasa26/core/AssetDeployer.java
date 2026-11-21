package com.gkeyes.lhasa26.core;

import android.content.res.AssetManager;

import java.io.InputStream;
import java.io.OutputStream;

/** Copies the supplied device-specific payloads through the already-authorized shell. */
public final class AssetDeployer {
    public static final String[] RUNTIME_ASSETS = {
            "reach_probe", "slide_probe", "uaf_plant_replay", "pc98260-su",
            "perf_slide", "ksud", "lhasa_profile.txt"
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
        if (process.exitValue() != 0) {
            throw new IllegalStateException("写入 " + assetName + " 失败：" + output);
        }
    }

    public interface WorkflowLog {
        void append(String line);
    }
}
