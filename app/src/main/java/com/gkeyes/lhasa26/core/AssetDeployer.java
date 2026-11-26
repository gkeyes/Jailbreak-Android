package com.gkeyes.lhasa26.core;

import android.content.res.AssetManager;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

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
     * 99491（CVE-2026-99491 real_cred / direct 引擎）的运行时资产。
     *
     * <p>最终设备流程（Lead 确认）：`cve99491_exp` + `lhasa_99491_profile.json` 放在
     * {@link #CVE99491_DIR}（exe 用 `./cve99491_exp`、`--profile ./profile.json`、`--workdir .`），
     * `kernelsu-android17-6.18.ko` 和 `ksud` 放在 `/data/local/tmp/`（exp 通过
     * CVE99491_KSU_KO / CVE99491_KSUD_BIN 环境变量引用）。ksud 走按需投放（4.9 MB，远端已校验则跳过）。
     *
     * <p>资产本体由 Lead 按 docs/99491-test-plan.md §4 放进 app/src/main/assets/；缺失时
     * {@link #stageAll(RootPath)} 会在开远端进程之前以明确错误优雅失败，不会崩、也不会跑一半才死。
     */
    public static final String[] RUNTIME_ASSETS_99491 = {
            AssetIntegrity.CVE99491_EXP_ASSET,
            Cve99491Profile.ASSET_NAME,
            AssetIntegrity.KSU_KO_ASSET
    };

    /** 99491 的工作目录（exp/profile/运行时标记都在这里；本 boot 的 one-fire guard 由 exp 维护）。 */
    public static final String CVE99491_DIR = "/data/local/tmp/cve99491";

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

    /** 包含按需投放资产（99491 需要 ksud）的完整必需清单。 */
    public static List<String> requiredAssets(RootPath path) {
        List<String> required = new ArrayList<>(Arrays.asList(assetsFor(path)));
        if (path == RootPath.WACOM_99491) {
            required.add(AssetIntegrity.KSUD_ASSET);
        }
        return required;
    }

    /**
     * 纯逻辑的缺件检测：APK 的 assets 清单里缺哪些必需文件（在开远端进程之前报错）。
     */
    public static List<String> missingAssets(RootPath path, Set<String> availableAssets) {
        List<String> missing = new ArrayList<>();
        for (String asset : requiredAssets(path)) {
            if (availableAssets == null || !availableAssets.contains(asset)) {
                missing.add(asset);
            }
        }
        return missing;
    }

    /** 资产的设备侧目标目录：99491 的 exp/profile 进专用工作目录，其余进 /data/local/tmp。 */
    public static String destinationFor(String assetName) {
        if (AssetIntegrity.CVE99491_EXP_ASSET.equals(assetName)
                || Cve99491Profile.ASSET_NAME.equals(assetName)) {
            return CVE99491_DIR;
        }
        return ShizukuExecutor.WORK_DIR;
    }

    /** 设备侧完整路径。 */
    public static String remotePath(String assetName) {
        return destinationFor(assetName) + "/" + assetName;
    }

    /**
     * 落盘权限：可执行资产 0755（exp/ksud/98260 探针），纯数据资产 0644（ko/profile）。
     *
     * <p>ko 不需要执行位；profile 更不能带执行位（避免被误当程序跑）。
     */
    public static String modeFor(String assetName) {
        if (AssetIntegrity.KSU_KO_ASSET.equals(assetName)
                || Cve99491Profile.ASSET_NAME.equals(assetName)) {
            return "644";
        }
        return "755";
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

    /**
     * 按路径部署：
     * <ul>
     *   <li>98260 走原 {@link #stageAll()}（一字不改）；</li>
     *   <li>99491 走"按需投放"：已配置 size/sha256 的资产在设备上校验通过就跳过（ksud 4.9 MB 不重传），
     *       每次都确保 exp/profile/ko/ksud 就位，日志带 `[99491]` 通道前缀。</li>
     * </ul>
     */
    public void stageAll(RootPath path) throws Exception {
        if (path == null || path == RootPath.TIMER_98260) {
            stageAll();
            return;
        }
        cancelled = false;
        String prefix = path.channel() + " ";
        for (String asset : requiredAssets(path)) {
            if (cancelled) {
                throw new IllegalStateException(prefix + "部署已被取消，停止后续写入");
            }
            ensure(asset, prefix);
        }
    }

    /** 按需投放：远端文件已存在且 size/sha256 校验通过就跳过，否则重新写入。 */
    public void ensure(String assetName, String channelPrefix) throws Exception {
        if (isRemoteAssetCurrent(assetName)) {
            log.append((channelPrefix == null ? "" : channelPrefix)
                    + "跳过 " + remotePath(assetName) + "（已存在且校验通过）");
            return;
        }
        stage(assetName, channelPrefix);
    }

    /**
     * 远端文件是否已是期望版本。只有配置了期望值（size/sha256）的资产才可能判定为"当前"：
     * exp 的最终 size/sha 回填前总是重新部署，避免用旧二进制跑新链。
     */
    public boolean isRemoteAssetCurrent(String assetName) {
        if (!AssetIntegrity.hasExpectations(assetName)) {
            return false;
        }
        String path = remotePath(assetName);
        String command = "p='" + path + "'; s=$(stat -c %s \"$p\" 2>/dev/null); "
                + "h=$(sha256sum \"$p\" 2>/dev/null | cut -d' ' -f1); "
                + "echo \"__SIZE__=$s\"; echo \"__SHA__=$h\"";
        try {
            String output = executor.run(command, true).output;
            long size = -1L;
            String sha = "";
            for (String line : output.split("\\n")) {
                String trimmed = line.trim();
                if (trimmed.startsWith("__SIZE__=")) {
                    try {
                        size = Long.parseLong(trimmed.substring("__SIZE__=".length()).trim());
                    } catch (NumberFormatException ignored) {
                        size = -1L;
                    }
                } else if (trimmed.startsWith("__SHA__=")) {
                    sha = trimmed.substring("__SHA__=".length()).trim();
                }
            }
            if (size <= 0L) {
                return false;
            }
            return AssetIntegrity.verify(assetName, size, sha).isOk();
        } catch (Exception ignored) {
            return false;
        }
    }

    public void stage(String assetName) throws Exception {
        stage(assetName, null);
    }

    /**
     * 投放单个资产。
     *
     * <p>边传边算 sha256，落盘后立刻与本类/资产台账里的期望值比对：不匹配就删掉远端文件并
     * fail-closed（绝不让一个损坏的 ksud/ko/exp 被后面的提权链执行到）。
     *
     * @param channelPrefix 日志通道前缀（如 `[99491] `），null 时保持历史日志格式
     */
    public void stage(String assetName, String channelPrefix) throws Exception {
        if (cancelled) {
            throw new IllegalStateException("部署已被取消，跳过 " + assetName);
        }
        String prefix = channelPrefix == null ? "" : channelPrefix;
        String destination = remotePath(assetName);
        String directory = destinationFor(assetName);
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
        Process process = executor.open("mkdir -p '" + directory + "'"
                + " && cat > '" + destination + ".new'"
                + " && chmod " + modeFor(assetName) + " '" + destination + ".new'"
                + " && mv -f '" + destination + ".new' '" + destination + "'");
        inFlight = process;
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException unsupported) {
            digest = null;
        }
        long written = 0L;
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
                        written += count;
                        if (digest != null) {
                            digest.update(buffer, 0, count);
                        }
                    }
                }
            }
            String output = CommandExecutor.readProcessOutput(process);
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IllegalStateException(prefix + "写入 " + assetName + " 失败：" + output);
            }
            String sha256 = digest == null ? "" : AssetIntegrity.toHex(digest.digest());
            AssetIntegrity.Verdict verdict = AssetIntegrity.verify(assetName, written, sha256);
            if (!verdict.isOk()) {
                deleteRemote(destination);
                throw new IllegalStateException(prefix + "资产校验失败，已删除远端文件并停止：" + verdict.detail);
            }
            if (AssetIntegrity.hasExpectations(assetName)) {
                log.append(prefix + "校验通过：" + verdict.detail);
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

    private void deleteRemote(String path) {
        try {
            executor.run("rm -f '" + path + "' 2>/dev/null; true", true);
        } catch (Exception ignored) {
            // 删除失败也不能让原错误被掩盖：后面的执行会因 deploy 失败被拦下。
        }
    }

    public interface WorkflowLog {
        void append(String line);
    }
}
