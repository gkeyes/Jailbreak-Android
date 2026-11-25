package com.gkeyes.lhasa26.core;

/**
 * 两条提权路径的选择。
 *
 * <p>98260 = 现有定时器 UAF 链（默认、稳定）；99491 = WACOM real_cred 链（CVE-2026-99491，
 * opt-in）。键名写进 SharedPreferences（{@code root_path}），必须保持稳定——发布后改键等于让老用户
 * 的选择失效。
 *
 * <p>选择错误时一律回落到 {@link #TIMER_98260}：98260 是已验证的链，把用户放进一条没标定过的路径
 * 不是"更激进"，而是"不可用"。
 */
public enum RootPath {
    TIMER_98260("TIMER_98260", "98260 · 定时器 UAF", "98260", false),
    WACOM_99491("WACOM_99491", "99491 · WACOM real_cred", "99491", true);

    /** 未选择 / 选择非法时的默认路径。 */
    public static final RootPath DEFAULT = TIMER_98260;

    private final String key;
    private final String label;
    private final String channel;
    private final boolean cve99491;

    RootPath(String key, String label, String channel, boolean cve99491) {
        this.key = key;
        this.label = label;
        this.channel = channel;
        this.cve99491 = cve99491;
    }

    /** 持久化键：`TIMER_98260` / `WACOM_99491`。 */
    public String key() {
        return key;
    }

    /** UI 展示名。 */
    public String label() {
        return label;
    }

    /** 日志通道前缀：`[98260]` / `[99491]`。 */
    public String channel() {
        return "[" + channel + "]";
    }

    public boolean isCve99491() {
        return cve99491;
    }

    /**
     * 解析持久化值。null / 空白 / 未知值都回落默认 98260（fail-safe），
     * 这样一次版本升级或手改 prefs 不会把用户带到未标定链上。
     */
    public static RootPath fromKey(String stored) {
        if (stored == null) {
            return DEFAULT;
        }
        String value = stored.trim();
        if (value.isEmpty()) {
            return DEFAULT;
        }
        for (RootPath path : values()) {
            if (path.key.equalsIgnoreCase(value) || path.name().equalsIgnoreCase(value)) {
                return path;
            }
        }
        return DEFAULT;
    }
}
