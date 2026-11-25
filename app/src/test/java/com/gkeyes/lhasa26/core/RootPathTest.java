package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * 路径选择与持久化键的纯逻辑验收。
 *
 * <p>持久化值来自 SharedPreferences（`root_path`），由 ConsoleActivity 读取后交给
 * {@link RootPath#fromKey(String)}。这里覆盖"读不到 / 值坏了"的回落行为：宁可回到已验证的
 * 98260，也不能把用户带进未标定链。
 */
public class RootPathTest {

    @Test
    public void defaultPathIsTheVerifiedTimerChain() {
        assertEquals(RootPath.TIMER_98260, RootPath.DEFAULT);
        assertEquals(RootPath.TIMER_98260, RootPath.fromKey(null));
        assertEquals(RootPath.TIMER_98260, RootPath.fromKey(""));
        assertEquals(RootPath.TIMER_98260, RootPath.fromKey("   "));
        assertEquals(RootPath.TIMER_98260, RootPath.fromKey("WACOM_99492"));
        assertEquals(RootPath.TIMER_98260, RootPath.fromKey("98260-ish"));
    }

    @Test
    public void persistedKeysRoundTrip() {
        for (RootPath path : RootPath.values()) {
            assertEquals(path, RootPath.fromKey(path.key()));
            // 大小写宽容：手改 prefs / 未来迁移不该让选择失效成默认值以外的路径
            assertEquals(path, RootPath.fromKey(path.key().toLowerCase(java.util.Locale.US)));
            assertEquals(path, RootPath.fromKey(path.name()));
        }
    }

    @Test
    public void keysAndChannelsAreStable() {
        assertEquals("TIMER_98260", RootPath.TIMER_98260.key());
        assertEquals("WACOM_99491", RootPath.WACOM_99491.key());
        assertEquals("[98260]", RootPath.TIMER_98260.channel());
        assertEquals("[99491]", RootPath.WACOM_99491.channel());
        assertNotEquals(RootPath.TIMER_98260.key(), RootPath.WACOM_99491.key());
        assertTrue(RootPath.TIMER_98260.label().contains("98260"));
        assertTrue(RootPath.WACOM_99491.label().contains("99491"));
    }

    @Test
    public void onlyWacomPathIsTheCve99491Chain() {
        assertFalse(RootPath.TIMER_98260.isCve99491());
        assertTrue(RootPath.WACOM_99491.isCve99491());
    }

    /** 持久化层只存 key，读出后回落的路径必须还是同一个（模拟一次重启后的恢复）。 */
    @Test
    public void storedValueSurvivesReloadLikeARestart() {
        String stored = RootPath.WACOM_99491.key();
        RootPath reloaded = RootPath.fromKey(stored);
        assertEquals(RootPath.WACOM_99491, reloaded);
        assertEquals(stored, reloaded.key());

        // 老版本/损坏的 prefs 值 → 回到默认 98260
        assertEquals(RootPath.TIMER_98260, RootPath.fromKey("99491"));
        assertEquals(RootPath.TIMER_98260, RootPath.fromKey("not-a-path"));
    }
}
