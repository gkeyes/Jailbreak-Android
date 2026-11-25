package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;

import org.junit.Test;

/**
 * 资产清单按路径分离的验收：99491 的资产名固定为 `cve99491_exp` + `lhasa_99491_profile.json`，
 * 98260 的历史清单不变（行为不能回归）。
 */
public class AssetDeployerPathTest {

    @Test
    public void cve99491AssetsAreTheAgreedNames() {
        assertArrayEquals(
                new String[]{"cve99491_exp", "lhasa_99491_profile.json"},
                AssetDeployer.assetsFor(RootPath.WACOM_99491));
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
    }

    @Test
    public void profileAssetNameMatchesTheProfileContract() {
        assertEquals(Cve99491Profile.ASSET_NAME, AssetDeployer.RUNTIME_ASSETS_99491[1]);
        assertEquals("cve99491_exp", AssetDeployer.RUNTIME_ASSETS_99491[0]);
    }

    /** 资产生命周期由 Lead 管：代码里不能悄悄依赖 99491 清单以外的资产。 */
    @Test
    public void cve99491ListDoesNotContainTimerOnlyBinaries() {
        String[] assets = AssetDeployer.assetsFor(RootPath.WACOM_99491);
        for (String asset : assets) {
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
