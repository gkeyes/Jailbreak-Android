package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 资产清单按路径分离的验收。
 *
 * <p>最终流程（Lead 确认）：99491 需要 {@code cve99491_exp} + {@code lhasa_99491_profile.json}
 * （投放到专用工作目录 /data/local/tmp/cve99491）以及 {@code kernelsu-android17-6.18.ko} +
 * {@code ksud}（投放到 /data/local/tmp）；98260 的历史清单/行为不能回归。
 */
public class AssetDeployerPathTest {

    @Test
    public void cve99491AssetsAreTheFinalNames() {
        assertArrayEquals(
                new String[]{
                        "cve99491_exp",
                        "lhasa_99491_profile.json",
                        "kernelsu-android17-6.18.ko"
                },
                AssetDeployer.assetsFor(RootPath.WACOM_99491));
    }

    @Test
    public void cve99491RequiredAssetsIncludeOnDemandKsud() {
        List<String> required = AssetDeployer.requiredAssets(RootPath.WACOM_99491);
        assertTrue(required.contains("ksud"));
        assertTrue(required.contains("cve99491_exp"));
        assertTrue(required.contains("kernelsu-android17-6.18.ko"));
        assertTrue(required.contains(Cve99491Profile.ASSET_NAME));
        assertEquals(4, required.size());
    }

    @Test
    public void timerAssetsAreUnchanged() {
        assertArrayEquals(AssetDeployer.RUNTIME_ASSETS,
                AssetDeployer.assetsFor(RootPath.TIMER_98260));
        assertArrayEquals(
                new String[]{"slide_probe", "uaf_plant_replay", "pc98260-su"},
                AssetDeployer.assetsFor(RootPath.TIMER_98260));
        assertArrayEquals(AssetDeployer.RUNTIME_ASSETS,
                AssetDeployer.assetsFor(null));
        // 98260 的预部署清单里没有 ksud（按需投放），保持历史语义
        assertEquals(Arrays.asList(AssetDeployer.RUNTIME_ASSETS),
                AssetDeployer.requiredAssets(RootPath.TIMER_98260));
    }

    @Test
    public void destinationsFollowTheFinalDeviceFlow() {
        String workDir = AssetDeployer.CVE99491_DIR;
        assertEquals("/data/local/tmp/cve99491", workDir);
        assertEquals(workDir, AssetDeployer.destinationFor("cve99491_exp"));
        assertEquals(workDir, AssetDeployer.destinationFor(Cve99491Profile.ASSET_NAME));
        assertEquals("/data/local/tmp", AssetDeployer.destinationFor("kernelsu-android17-6.18.ko"));
        assertEquals("/data/local/tmp", AssetDeployer.destinationFor("ksud"));
        assertEquals("/data/local/tmp", AssetDeployer.destinationFor("slide_probe"));
        assertEquals(workDir + "/cve99491_exp", AssetDeployer.remotePath("cve99491_exp"));
        assertEquals("/data/local/tmp/ksud", AssetDeployer.remotePath("ksud"));
    }

    /** 可执行资产 0755，数据资产 0644（ko 不需要执行位；profile 不能带执行位）。 */
    @Test
    public void permissionModesMatchAssetKind() {
        assertEquals("755", AssetDeployer.modeFor("cve99491_exp"));
        assertEquals("755", AssetDeployer.modeFor("ksud"));
        assertEquals("755", AssetDeployer.modeFor("uaf_plant_replay"));
        assertEquals("755", AssetDeployer.modeFor("slide_probe"));
        assertEquals("644", AssetDeployer.modeFor(AssetIntegrity.KSU_KO_ASSET));
        assertEquals("644", AssetDeployer.modeFor(Cve99491Profile.ASSET_NAME));
    }

    @Test
    public void missingAssetDetectionIsFailClosed() {
        Set<String> available = new HashSet<>(Arrays.asList(
                "cve99491_exp", Cve99491Profile.ASSET_NAME, "ksud", "slide_probe"));
        List<String> missing = AssetDeployer.missingAssets(RootPath.WACOM_99491, available);
        assertEquals(Arrays.asList("kernelsu-android17-6.18.ko"), missing);

        Set<String> onlyTimer = new HashSet<>(Arrays.asList(
                "uaf_plant_replay", "slide_probe", "pc98260-su"));
        missing = AssetDeployer.missingAssets(RootPath.WACOM_99491, onlyTimer);
        assertTrue(missing.contains("cve99491_exp"));
        assertTrue(missing.contains(Cve99491Profile.ASSET_NAME));
        assertTrue(missing.contains("kernelsu-android17-6.18.ko"));
        assertTrue(missing.contains("ksud"));

        // 98260 的缺件检测只看自己的清单（ksud 不在预部署清单里）
        missing = AssetDeployer.missingAssets(RootPath.TIMER_98260, onlyTimer);
        assertTrue(missing.isEmpty());
        assertFalse(AssetDeployer.missingAssets(RootPath.TIMER_98260, new HashSet<>()).isEmpty());
    }

    /** 资产生命周期由 Lead 管：代码里不能悄悄依赖 99491 清单以外的资产。 */
    @Test
    public void cve99491ListDoesNotContainTimerOnlyBinaries() {
        for (String asset : AssetDeployer.assetsFor(RootPath.WACOM_99491)) {
            assertFalse("99491 不应部署 98260 专属资产：" + asset,
                    "uaf_plant_replay".equals(asset) || "slide_probe".equals(asset)
                            || "pc98260-su".equals(asset));
        }
    }

    @Test
    public void assetsForReturnsDefensiveCopies() {
        String[] cve = AssetDeployer.assetsFor(RootPath.WACOM_99491);
        assertNotSame(AssetDeployer.RUNTIME_ASSETS_99491, cve);
        cve[0] = "tampered";
        assertEquals("cve99491_exp", AssetDeployer.RUNTIME_ASSETS_99491[0]);

        String[] timer = AssetDeployer.assetsFor(RootPath.TIMER_98260);
        assertNotSame(AssetDeployer.RUNTIME_ASSETS, timer);
        timer[0] = "tampered";
        assertEquals("slide_probe", AssetDeployer.RUNTIME_ASSETS[0]);
    }
}
