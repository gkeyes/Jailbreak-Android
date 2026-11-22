package com.gkeyes.lhasa26.core;

import java.util.regex.Pattern;

/**
 * 日志导出前的脱敏。
 *
 * 导出的日志会被贴到群里、issue 里，里面不该出现能定位到某个人的东西。
 * 这里只处理"一看就知道是标识符"的几类，不做过度替换——调试需要的路径、内核
 * 版本、寄存器地址一律保留，否则日志就没用了。
 */
public final class LogRedactor {

    private static final String MASK = "***";

    private static final Pattern IPV4 = Pattern.compile(
            "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final Pattern MAC = Pattern.compile(
            "\\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\\b");
    private static final Pattern EMAIL = Pattern.compile(
            "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
    private static final Pattern CN_MOBILE = Pattern.compile(
            "(?<!\\d)1[3-9]\\d{9}(?!\\d)");
    /** 序列号/设备 ID 这类：12 位以上、字母数字混排、至少含 4 个数字。 */
    private static final Pattern SERIAL = Pattern.compile(
            "\\b(?=[A-Za-z0-9]{12,40}\\b)(?=(?:[^0-9]*[0-9]){4})[A-Za-z0-9]{12,40}\\b");
    /** 显式的键值对：serial=xxx、imei: xxx、token=xxx。 */
    private static final Pattern SENSITIVE_KV = Pattern.compile(
            "(?i)\\b(serial|imei|imsi|android_id|token|password|passwd|secret)\\b\\s*[=:]\\s*\\S+");

    private LogRedactor() {
    }

    public static String redact(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String out = text;
        out = EMAIL.matcher(out).replaceAll(MASK);
        out = MAC.matcher(out).replaceAll(MASK);
        out = IPV4.matcher(out).replaceAll(MASK);
        out = CN_MOBILE.matcher(out).replaceAll(MASK);
        out = SERIAL.matcher(out).replaceAll(MASK);
        out = SENSITIVE_KV.matcher(out).replaceAll("$1=" + MASK);
        return out;
    }
}
