package com.gkeyes.lhasa26.core;

import android.content.res.AssetManager;

import java.io.IOException;
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

    /**
     * 99491（real_cred 链）的运行时资产。
     *
     * <p>资产本体由 Lead 按 docs/99491-test-plan.md §4 放进 app/src/main/assets/；缺失时
     * {@link #stageAll(RootPath)} 会以明确错误优雅失败，不会崩、也不会静默跳过而跑到一半才死。
     * profile 只读校验在 {@link Cve99491Profile}，这里只负责投放。
     */
    public static final String[] RUNTIME_ASSETS_99491 = {
            "cve99491_exp", Cve99491Profile.ASSET_NAME
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

    /** 某条提权路径需要的运行时资产清单（防御性拷贝，调用方改不动常量表）。 */
    public static String[] assetsFor(RootPath path) {
        if (path == RootPath.WACOM_99491) {
            return RUNTIME_ASSETS_99491.clone();
        }
        return RUNTIME_ASSETS.clone();
    }

    /** 98260 链的部署入口：行为与历史版本完全一致（日志不带通道前缀）。 */
    public void stageAll() throws Exception {
        cancelled = false;
        for (String asset : RUNTIME_ASSETS) {
            if (cancelled) {
                throw new IllegalStateException("部署已被取消，停止后续写入");
            }
            stage(asset);
        }
    }

    /** 按路径部署；98260 走原 {@link #stageAll()}，99491 走自己的资产表并带 `[99491]` 通道前缀。 */
    public void stageAll(RootPath path) throws Exception {
        if (path == null || path == RootPath.TIMER_98260) {
            stageAll();
            return;
        }
        cancelled = false;
        for (String asset : RUNTIME_ASSETS_99491) {
            if (cancelled) {
                throw new IllegalStateException(path.channel() + " 部署已被取消，停止后续写入");
            }
            stage(asset, path.channel() + " ");
        }
    }

    public void stage(String assetName) throws Exception {
        stage(assetName, null);
    }

    /**
     * 投放单个资产。
     *
     * @param channelPrefix 日志通道前缀（如 `[99491] `），null 时保持历史日志格式
     */
    public void stage(String assetName, String channelPrefix) throws Exception {
        if (cancelled) {
            throw new IllegalStateException("部署已被取消，跳过 " + assetName);
        }
        String prefix = channelPrefix == null ? "" : channelPrefix;
        String destination = ShizukuExecutor.WORK_DIR + "/" + assetName;
        // 先确认 APK 里真的有这个资产，再开远端进程：缺件是最常见的失败，
        // 要在动用 shell / 写远端之前就给出明确错误。
        InputStream input;
        try {
            input = assets.open(assetName);
        } catch (IOException missing) {
            throw new IllegalStateException(prefix + "资产缺失：" + assetName
                    + "（APK 内未找到该文件，需要放入 app/src/main/assets/；不会继续执行）", missing);
        }
        log.append(prefix + "部署 " + destination);
        Process process = executor.open("cat > '" + destination + ".new'"
                + " && chmod 755 '" + destination + ".new'"
                + " && mv -f '" + destination + ".new' '" + destination + "'");
        inFlight = process;
        boolean finished = false;
        try {
            try (InputStream in = input;
                 OutputStream output = process.getOutputStream()) {
                byte[] buffer = new byte[65536];
                int count;
                while ((count = in.read(buffer)) >= 0) {
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
                throw new IllegalStateException(prefix + "写入 " + assetName + " 失败：" + output);
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
