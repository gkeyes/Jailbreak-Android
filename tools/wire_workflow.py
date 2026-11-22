#!/usr/bin/env python3
"""把 BootGuard / DeployGate 接到 WorkflowEngine 的真实入口。

不用 patch / diff：hunk 行号与行数太容易写错，git apply 会整份拒绝。
这里改为锚点式替换，每处断言“恰好命中一次”，不命中就报错退出，绝不静默跳过。

幂等粒度是“逐处”：已替换过的位置（锚点不在但替换结果在）直接跳过，
新加的替换项仍能补到已经接好线的文件上。
"""
from __future__ import annotations

import pathlib
import sys

TARGET = pathlib.Path("app/src/main/java/com/gkeyes/lhasa26/core/WorkflowEngine.java")

REPLACEMENTS: list[tuple[str, str, str]] = [
    (
        "DEPLOY_TIMEOUT_MS 常量",
        '    private static final long CLEAN_SKIP_AVAILABLE_KB = 3000000L;\n',
        '    private static final long CLEAN_SKIP_AVAILABLE_KB = 3000000L;\n'
        '    private static final long DEPLOY_TIMEOUT_MS = 8000L;\n',
    ),
    (
        "内核不匹配警告",
        '        if (!KernelSupport.isSupported(kernel)) {\n'
        '            append("（警告）当前内核不在已验证列表，仍继续，风险自负。");\n'
        '        }\n',
        '        if (!BootGuard.isSupportedKernel(kernel)) {\n'
        '            append(BootGuard.kernelWarning(kernel));\n'
        '        }\n',
    ),
    (
        "部署闸门",
        '        deploy.join(8000L);\n'
        '        if (deployError.get() != null) {\n'
        '            throw deployError.get();\n'
        '        }\n',
        '        DeployGate.Result deployResult = new DeployGate(DEPLOY_TIMEOUT_MS)\n'
        '                .await(deploy, deployError);\n'
        '        if (deployResult != DeployGate.Result.READY) {\n'
        '            recordFailedBoot(boot);\n'
        '            throw new IllegalStateException("部署未完成（" + deployResult + "）· 请重启后重试");\n'
        '        }\n',
    ),
    (
        "runPayload 调用点",
        '        if (!runPayload(addressArgument)) {\n',
        '        if (!runPayload(addressArgument, boot)) {\n',
    ),
    (
        "runPayload 签名",
        '    private boolean runPayload(String addressArgument) throws Exception {\n',
        '    private boolean runPayload(String addressArgument, String boot) throws Exception {\n',
    ),
    (
        "payload 启动命令",
        '            run("rm -f /data/local/tmp/uaf_replay.log; toybox setsid sh -c \'/data/local/tmp/uaf_plant_replay "\n'
        '                    + addressArgument + " > /data/local/tmp/uaf_replay.log 2>&1 < /dev/null\' >/dev/null 2>&1 & echo STARTED", true);\n',
        '            run("rm -f /data/local/tmp/uaf_replay.log; " + BootGuard.launchCommand(\n'
        '                    "/data/local/tmp/uaf_plant_replay",\n'
        '                    addressArgument,\n'
        '                    "/data/local/tmp/uaf_replay.log"), true);\n',
    ),
    (
        "成功标记判定",
        '                if (containsSuccessMarker(tail)) {\n'
        '                    return true;\n'
        '                }\n',
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
        '                if (containsRetryMarker(tail)) {\n',
        '                if (outcome == BootGuard.Outcome.RETRY_SAFE) {\n',
    ),
    (
        "删除两个旧标记方法",
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
        '\n',
        '',
    ),
    (
        "stopPayload 改为进程组信号",
        '        run("pkill -f uaf_plant_replay 2>/dev/null; killall uaf_plant_replay 2>/dev/null; true", true);\n',
        '        run(BootGuard.killCommand(), true);\n',
    ),
    (
        "cleanupBinaries 也改用进程组信号",
        '            if (!keepRootClient) {\n'
        '                run("pkill -f uaf_plant_replay 2>/dev/null; true", true);\n'
        '            }\n',
        '            if (!keepRootClient) {\n'
        '                run(BootGuard.killCommand(), true);\n'
        '            }\n',
    ),
    (
        "payloadProcessCount 改用 kill -0",
        '        String output = run("ps -A 2>/dev/null | grep -c \'[u]af_plant_replay\'", true).output.trim();\n'
        '        int count;\n'
        '        try {\n'
        '            count = Integer.parseInt(output);\n'
        '        } catch (NumberFormatException ignored) {\n'
        '            count = RUNNING_PAYLOAD.matcher(output).find() ? 1 : 0;\n'
        '        }\n',
        '        int count = Integer.parseInt(run(BootGuard.aliveCommand(), true).output.trim());\n',
    ),
]


def main() -> int:
    source = TARGET.read_text(encoding="utf-8")

    applied = 0
    skipped = 0
    failures: list[str] = []

    for label, needle, replacement in REPLACEMENTS:
        hits = source.count(needle)
        if hits == 1:
            source = source.replace(needle, replacement)
            applied += 1
            continue
        if hits == 0 and replacement and replacement in source:
            skipped += 1
            continue
        if hits == 0 and not replacement:
            skipped += 1
            continue
        failures.append(f"{label}: 锚点命中 {hits} 次（应为 1）")

    if failures:
        for line in failures:
            print(f"::error::{line}")
        return 1

    TARGET.write_text(source, encoding="utf-8")
    print(f"applied={applied} skipped={skipped}")
    print(f"BootGuard.classify: {source.count('BootGuard.classify')}")
    print(f"DeployGate:         {source.count('DeployGate')}")
    print(f"DEPLOY_TIMEOUT_MS:  {source.count('DEPLOY_TIMEOUT_MS')}")

    for leftover in ("containsSuccessMarker", "containsRetryMarker",
                     "pkill -f uaf_plant_replay", "killall uaf_plant_replay"):
        remaining = source.count(leftover)
        if remaining:
            print(f"::error::仍残留 {leftover} x{remaining}")
            return 1
    print("no leftovers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
