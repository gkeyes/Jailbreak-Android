package com.gkeyes.lhasa26.core;

public final class DeviceSnapshot {
    public final String device;
    public final String build;
    public final String kernel;

    public DeviceSnapshot(String device, String build, String kernel) {
        this.device = emptyAsDash(device);
        this.build = emptyAsDash(build);
        this.kernel = emptyAsDash(kernel);
    }

    public boolean isKernelSupported() {
        return KernelSupport.isSupported(kernel);
    }

    private static String emptyAsDash(String value) {
        return value == null || value.trim().isEmpty() ? "—" : value.trim();
    }
}
