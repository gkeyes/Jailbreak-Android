package com.gkeyes.lhasa26.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * 两条链的 step 标签必须按路径区分：UI 进度条文案随路径变化，但 98260 的标签一个都不能改。
 */
public class WorkflowEngineLabelsTest {

    @Test
    public void timerLabelsAreUnchanged() {
        assertArrayEquals(WorkflowEngine.STEP_LABELS,
                WorkflowEngine.stepLabels(RootPath.TIMER_98260));
        assertArrayEquals(new String[]{
                        "校验内核", "部署程序", "测量内核地址", "等待系统空闲",
                        "提权执行", "结果验证", "KernelSU 接管"},
                WorkflowEngine.stepLabels(RootPath.TIMER_98260));
    }

    @Test
    public void cve99491LabelsArePathSpecific() {
        String[] labels = WorkflowEngine.stepLabels(RootPath.WACOM_99491);
        assertEquals(WorkflowEngine.STEP_LABELS_99491.length, labels.length);
        assertEquals("校验 profile", labels[0]);
        assertEquals("KernelSU 接管", labels[labels.length - 1]);
        assertTrue(Arrays.toString(labels), Arrays.asList(labels).contains("real_cred 写原语"));
        assertTrue(Arrays.toString(labels), Arrays.asList(labels).contains("SELinux 切换"));
        // 两条链的步骤文案必须能区分，否则日志导出无法归因
        assertFalse(Arrays.equals(WorkflowEngine.STEP_LABELS, labels));
    }

    @Test
    public void stepLabelsAreUniqueWithinEachPath() {
        for (RootPath path : RootPath.values()) {
            String[] labels = WorkflowEngine.stepLabels(path);
            Set<String> unique = new HashSet<>(Arrays.asList(labels));
            assertEquals(path.key() + " 的步骤文案重复", labels.length, unique.size());
            for (String label : labels) {
                assertFalse(path.key() + " 步骤标签为空", label.trim().isEmpty());
            }
        }
    }

    @Test
    public void stepLabelsReturnDefensiveCopies() {
        String[] first = WorkflowEngine.stepLabels(RootPath.WACOM_99491);
        assertNotSame(WorkflowEngine.STEP_LABELS_99491, first);
        first[0] = "tampered";
        assertEquals("校验 profile", WorkflowEngine.STEP_LABELS_99491[0]);

        String[] timer = WorkflowEngine.stepLabels(RootPath.TIMER_98260);
        assertNotSame(WorkflowEngine.STEP_LABELS, timer);
        timer[0] = "tampered";
        assertEquals("校验内核", WorkflowEngine.STEP_LABELS[0]);
    }

    @Test
    public void unknownPathFallsBackToTimerLabels() {
        assertArrayEquals(WorkflowEngine.STEP_LABELS, WorkflowEngine.stepLabels(null));
    }

    @Test
    public void deployTimeoutIsConfigurablePerPath() {
        assertTrue("99491 资产更大，部署超时应更宽",
                WorkflowEngine.deployTimeoutMs(RootPath.WACOM_99491)
                        > WorkflowEngine.deployTimeoutMs(RootPath.TIMER_98260));
        assertEquals(WorkflowEngine.deployTimeoutMs(RootPath.TIMER_98260),
                WorkflowEngine.deployTimeoutMs(null));
        assertTrue(WorkflowEngine.deployTimeoutMs(RootPath.WACOM_99491) > 0L);
    }

    /** 锁住 Lead 真机验收过的调用形态：cwd/env/--stage=root/相对路径都不能漂。 */
    @Test
    public void cve99491RunCommandMatchesTheValidatedDeviceFlow() {
        String command = WorkflowEngine.cve99491RunCommand();
        assertEquals("/data/local/tmp/cve99491", WorkflowEngine.cve99491WorkDir());
        assertTrue(command, command.startsWith("cd /data/local/tmp/cve99491 && "));
        assertTrue(command, command.contains("CVE99491_KSU_BACKEND=ko"));
        assertTrue(command, command.contains("CVE99491_KSUD_BIN=/data/local/tmp/ksud"));
        assertTrue(command, command.contains(
                "CVE99491_KSU_KO=/data/local/tmp/kernelsu-android17-6.18.ko"));
        assertTrue(command, command.contains("CVE99491_TIMING=1"));
        assertTrue(command, command.contains("--stage=root"));
        assertTrue(command, command.contains("./cve99491_exp"));
        assertTrue(command, command.contains("--profile ./lhasa_99491_profile.json"));
        assertTrue(command, command.contains("--workdir ."));
        // 旧骨架是 --stage=full 且没有 ko env；这两个组合绝不能再出现
        assertFalse(command, command.contains("--stage=full"));
        assertFalse(command, command.contains("--stage=")
                && !command.contains("--stage=root"));
        assertEquals("/data/local/tmp/kernelsu-android17-6.18.ko",
                WorkflowEngine.cve99491KsuKoPath());
    }
}
