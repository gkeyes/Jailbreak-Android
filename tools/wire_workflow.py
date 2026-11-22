#!/usr/bin/env python3
"""把 BootGuard / DeployGate 接到 WorkflowEngine 的真实入口。

不用 patch / diff：hunk 行号与行数太容易写错，git apply 会整份拒绝。
锚点式替换，每处断言“恰好命中一次”，不命中就报错退出。

幂等判断必须“先看结果、再看锚点”。
反例：常量那条的锚点（CLEAN_SKIP_AVAILABLE_KB 那一行）在替换后仍然存在，
如果先看锚点就会每次都再揥一次，造成变量重复定义。
"""
from __future__ import annotations

import pathlib
import sys

TARGET = pathlib.Path("app/src/main/java/com/gkeyes/lhasa26/core/WorkflowEngine.java")

THREAD_OLD = (
    '        final java.util.concurrent.atomic.AtomicReference<Exception> deployError =\n'
    '                new java.util.concurrent.atomic.AtomicReference<>();\n'
    '        Thread deploy = new Thread(() -> {\n'
    '            try {\n'
    '                deployer.stageAll();\n'
    '            } catch (Exception error) {\n'
    '                deployError.set(error);\n'
    '            }\n'
    '        }, "lhasa-deploy");\n'
)

THREAD_NEW = (
    '        final DeployGate deployGate = new DeployGate(DEPLOY_TIMEOUT_MS);\n'
    '        Thread deploy = new Thread(() -> {\n'
    '            try {\n'
    '                deployer.stageAll();\n'
    '                deployGate.markCompleted();\n'
    '            } catch (Throwable error) {\n'
    '                deployGate.fail(error);\n'
    '            }\n'
    '        }, "lhasa-deploy");\n'
)

GATE_BASELINE = (
    '        deploy.join(8000L);\n'
    '        if (deployError.get() != null) {\n'
    '            throw deployError.get();\n'
    '        }\n'
)

GATE_OLD_WIRED = (
    '        DeployGate.Result deployResult = new DeployGate(DEPLOY_TIMEOUT_MS)\n'
    '                .await(deploy, deployError);\n'
)

GATE_NEW = '        DeployGate.Result deployResult = deployGate.await(deploy);\n'

CHANGES: list[tuple[str, list[str], str]] = [
    (
        "DEPLOY_TIMEOUT_MS 常量",
        [
            '    private static final long CLEAN_SKIP_AVAILABLE_KB = 3000000L;\n'
            '    private static final Pattern RUNNING_PAYLOAD'
        ],
        '    private static final long CLEAN_SKIP_AVAILABLE_KB = 3000000L;\n'
        '    private static final long DEPLOY_TIMEOUT_MS = 8000L;\n'
        '    private static final Pattern RUNNING_PAYLOAD',
    ),
    (
        "内核不匹配警告",
        [
            '        if (!KernelSupport.isSupported(kernel)) {\n'
            '            append("（警告）当前内核不在已验证列表，仍继续，风险自负。");\n'
            '        }\n'
        ],
        '        if (!BootGuard.isSupportedKernel(kernel)) {\n'
        '            append(BootGuard.kernelWarning(kernel));\n'
        '        }\n',
    ),
    ("部署线程改为显式回报", [THREAD_OLD], THREAD_NEW),
    ("部署闸门调用", [GATE_BASELINE, GATE_OLD_WIRED], GATE_NEW),
    (
        "runPayload 调用点",
        ['        if (!runPayload(addressArgument)) {\n'],
        '        if (!runPayload(addressArgument, boot)) {\n',
    ),
    (
        "runPayload 签名",
        ['    private boolean runPayload(String addressArgument) throws Exception {\n'],
        '    private boolean runPayload(String addressArgument, String boot) throws Exception {\n',
    ),
    (
        "payload 启动命令",
        [
            '            run("rm -f /data/local/tmp/uaf_replay.log; toybox setsid sh -c \'/data/local/tmp/uaf_plant_replay "\n'
            '                    + addressArgument + " > /data/local/tmp/uaf_replay.log 2>&1 < /dev/null\' >/dev/null 2>&1 & echo STARTED", true);\n'
        ],
        '            run("rm -f /data/local/tmp/uaf_replay.log; " + BootGuard.launchCommand(\n'
        '                    "/data/local/tmp/uaf_plant_replay",\n'
        '                    addressArgument,\n'
        '                    "/data/local/tmp/uaf_replay.log"), true);\n',
    ),
    (
        "成功标记判定",
        [
            '                if (containsSuccessMarker(tail)) {\n'
            '                    return true;\n'
            '                }\n'
        ],
        '                BootGuard.Outcome outcome = BootGuard.classify(tail);\n'
        '                if (outcome == BootGuard.Outcome.SUCCESS) {\n'
        '                    return true;\n'
        '                }\n'
        '                if (outcome == BootGuard.Outcome.ABORT_BOOT) {\n'
        '                    recordFailedBoot(boot);\n'
        '                    throw new IllegalStateException(\n'
        '                            "payload 报告节点已挂树（holding zombie）· 本次开机终止，请重启设备");\n'
        '                }\n',
    ),
    (
        "重试标记判定",
        ['                if (containsRetryMarker(tail)) {\n'],
        '                if (outcome == BootGuard.Outcome.RETRY_SAFE) {\n',
    ),
    (
        "删除两个旧标记方法",
        [
            '    private boolean containsSuccessMarker(String tail) {\n'
            '        return tail.contains("[child-cred] uid=0")\n'
            '                || tail.contains("[cred] rooted")\n'
            '                || tail.contains("holding pages")\n'
            '                || tail.contains("[selinux] already permissive");\n'
            '    }\n'
            '\n'
            '    private boolean containsRetryMarker(String tail) {\n'
            '        return tail.contains("holding zombie")\n'
            '                || tail.contains("leak failed")\n'
            '                || tail.contains("[selinux] attempt 2/");\n'
            '    }\n'
            '\n'
        ],
        '',
    ),
    (
        "stopPayload 改为进程组信号",
        ['        run("pkill -f uaf_plant_replay 2>/dev/null; killall uaf_plant_replay 2>/dev/null; true", true);\n'],
        '        run(BootGuard.killCommand(), true);\n',
    ),
    (
        "cleanupBinaries 也改用进程组信号",
        [
            '            if (!keepRootClient) {\n'
            '                run("pkill -f uaf_plant_replay 2>/dev/null; true", true);\n'
            '            }\n'
        ],
        '            if (!keepRootClient) {\n'
        '                run(BootGuard.killCommand(), true);\n'
        '            }\n',
    ),
    (
        "payloadProcessCount 改用 kill -0",
        [
            '        String output = run("ps -A 2>/dev/null | grep -c \'[u]af_plant_replay\'", true).output.trim();\n'
            '        int count;\n'
            '        try {\n'
            '            count = Integer.parseInt(output);\n'
            '        } catch (NumberFormatException ignored) {\n'
            '            count = RUNNING_PAYLOAD.matcher(output).find() ? 1 : 0;\n'
            '        }\n'
        ],
        '        int count = Integer.parseInt(run(BootGuard.aliveCommand(), true).output.trim());\n',
    ),
]


def main() -> int:
    source = TARGET.read_text(encoding="utf-8")
    applied = 0
    skipped = 0
    failures: list[str] = []

    for label, needles, replacement in CHANGES:
        # 先看结果：已经改过的位置直接跳过，避免带前缀性质的锚点被重复揥入。
        if replacement and replacement in source:
            skipped += 1
            continue
        hit = None
        for needle in needles:
            if source.count(needle) == 1:
                hit = needle
                break
        if hit is not None:
            source = source.replace(hit, replacement)
            applied += 1
            continue
        if not replacement:
            skipped += 1
            continue
        counts = ", ".join(str(source.count(n)) for n in needles)
        failures.append(f"{label}: 候选锚点命中次数 [{counts}]，均不为 1")

    if failures:
        for line in failures:
            print(f"::error::{line}")
        return 1

    TARGET.write_text(source, encoding="utf-8")
    print(f"applied={applied} skipped={skipped}")
    for marker in ("BootGuard.classify", "DeployGate", "markCompleted", "DEPLOY_TIMEOUT_MS",
                   "deployError", "containsSuccessMarker", "containsRetryMarker",
                   "pkill -f uaf_plant_replay", "killall uaf_plant_replay"):
        print(f"{marker}: {source.count(marker)}")

    problems = []
    if source.count("DEPLOY_TIMEOUT_MS") > 2:
        problems.append("DEPLOY_TIMEOUT_MS 重复定义")
    for leftover in ("containsSuccessMarker", "containsRetryMarker", "deployError",
                     "pkill -f uaf_plant_replay", "killall uaf_plant_replay"):
        if source.count(leftover):
            problems.append(f"仍残留 {leftover}")
    if source.count("markCompleted") != 1:
        problems.append(f"markCompleted 出现 {source.count('markCompleted')} 次")

    if problems:
        for line in problems:
            print(f"::error::{line}")
        return 1
    print("clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
