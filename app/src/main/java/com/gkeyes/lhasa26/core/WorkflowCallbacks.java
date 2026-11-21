package com.gkeyes.lhasa26.core;

public interface WorkflowCallbacks {
    void onStatus(String status);

    void onLog(String line);

    void onTail(String tail);

    void onStep(int step, String label);

    void onDevice(DeviceSnapshot snapshot);

    void onState(WorkflowEngine.State state, String message);
}
