package com.gkeyes.lhasa26.core;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class KernelSupport {
    public static final String[] SUPPORTED_KERNELS = {
            "6.18.21-android17-5-g805aa6adea19-abogki565292102-4k",
            "6.18.21-android17-5-g284297031c53-abogki553682993-4k",
            "6.18.21-android17-5-g1d099fcb35e0-abogki538445360-4k"
    };

    /**
     * `slide=0x…`；上游用 printf("%#lx") 输出，slide 为 0 时实际打印的是 `slide=0`，
     * 所以这里不强制 0x 前缀，交给 {@link #extractSlide(String)} 归一化。
     */
    private static final Pattern SLIDE = Pattern.compile("slide=(0[xX][0-9a-fA-F]+|0(?![0-9a-fA-FxX]))");
    private static final Pattern CALC = Pattern.compile("calc=(0[xX][0-9a-fA-F]+)");
    private static final Pattern SITE = Pattern.compile("site=(0[xX][0-9a-fA-F]+)");

    private KernelSupport() {
    }

    public static boolean isSupported(String kernel) {
        if (kernel == null) {
            return false;
        }
        String value = kernel.trim();
        for (String supported : SUPPORTED_KERNELS) {
            if (supported.equals(value)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isSlideValid(long slide) {
        return (slide & 0x1FFFFFL) == 0
                && ((slide + (-272730423296L)) >>> 48) == 65535;
    }

    /** 返回可直接传 `--slide` 的值；`slide=0` 归一化成 `0x0`。 */
    public static String extractSlide(String output) {
        Matcher matcher = SLIDE.matcher(output == null ? "" : output);
        if (!matcher.find()) {
            return null;
        }
        String value = matcher.group(1);
        return value.startsWith("0x") || value.startsWith("0X") ? value : "0x0";
    }

    public static String extractCalc(String output) {
        Matcher matcher = CALC.matcher(output == null ? "" : output);
        return matcher.find() ? matcher.group(1) : null;
    }

    public static String extractSite(String output) {
        Matcher matcher = SITE.matcher(output == null ? "" : output);
        return matcher.find() ? matcher.group(1) : null;
    }

    public static long parseHex(String value) {
        if (value == null || !value.toLowerCase(Locale.US).startsWith("0x")) {
            return -1L;
        }
        try {
            return Long.parseLong(value.substring(2), 16);
        } catch (NumberFormatException ignored) {
            return -1L;
        }
    }
}
