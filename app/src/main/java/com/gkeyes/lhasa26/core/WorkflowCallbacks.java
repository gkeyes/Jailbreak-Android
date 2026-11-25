package com.gkeyes.lhasa26.core;

public interface WorkflowCallbacks {
    void onStatus(String status);

    void onLog(String line);

    void onTail(String tail);

    void onStep(int step, String label);

    void onDevice(DeviceSnapshot snapshot);

    void onState(WorkflowEngine.State state, String message);

    /**
     * 99491 profile 可用性结果（fail-closed）。
     *
     * <p>默认空实现，避免所有历史实现被迫修改；宿主（{@code ConsoleActivity}）覆盖它来
     * 在系统面板里显示"未适配 + 原因"并禁用路径切换。
     *
     * @param available profile 通过 release 精确匹配 + verified=true 校验
     * @param reason    不可用时的具体原因；可用时是人话摘要
     */
    default void onRootPathAvailability(boolean available, String reason) {
    }
}
