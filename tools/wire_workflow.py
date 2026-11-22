#!/usr/bin/env python3
"""把 BootGuard / DeployGate 接到 WorkflowEngine 的真实入口。

两次失败的教训：
  - git apply 对 hunk 行数校验严格，手写 diff 的数字写错就整份拒绝；
  - 多行精确字符串做锚点，文件一旦被改过一次就再也匹配不上。

所以部署相关三处改用正则做结构性替换（能同时适配基线、旧接线、新接线三种形态），
其余不需要变化的小改动继续用精确字符串。每条改动都断言“命中一次”。
"""
from __future__ import annotations

import pathlib
import re
import sys

TARGET = pathlib.Path("app/src/main/java/com/gkeyes/lhasa26/core/WorkflowEngine.java")

THREAD_NEW = (
    '        final DeployGate deployGate = new DeployGate(DEPLOY_TIMEOUT_MS);\n'
    '        Thread deploy = new Thread(() -> {\n'
    '            try {\n'
    '                deployer.stageAll();\n'
    '                deployGate.markCompleted();\n'
    '            } catch (Throwable error) {\n'
    '                deployGate.fail(error);\n'
    '            }\n'
    '        }, "lhasa-deploy");'
)

GATE_NEW = '        DeployGate.Result deployResult = deployGate.await(deploy);\n'

THREAD_RE = re.compile(
    r'        final java\.util\.concurrent\.atomic\.AtomicReference<Exception> deployError =\n'
    r'.*?\}, "lhasa-deploy"\);',
    re.S,
)

GATE_JOIN_RE = re.compile(
    r'        deploy\.join\(8000L\);\n'
    r'        if \(deployError\.get\(\) != null\) \{\n'
    r'            throw deployError\.get\(\);\n'
    r'        \}\n'
)

GATE_TWO_ARG_RE = re.compile(
    r'        DeployGate\.Result deployResult = .*?;\n',
    re.S,
)

CONST_RE = re.compile(r'(    private static final long CLEAN_SKIP_AVAILABLE_KB = 3000000L;\n)')
CONST_LINE = '    private static final long DEPLOY_TIMEOUT_MS = 8000L;\n'

STR_CHANGES: list[tuple[str, list[str], str]] = [
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
    log: list[str] = []

    # 1) 常量：单次插入，已有就不动。
    if "DEPLOY_TIMEOUT_MS" not in source:
        source, n = CONST_RE.subn(lambda m: m.group(1) + CONST_LINE, source, count=1)
        log.append(f"常量插入 {n}")
    else:
        log.append("常量已存在")

    # 2) 部署线程：基线（带 AtomicReference）或旧接线都能匹配。
    if "markCompleted" not in source:
        source, n = THREAD_RE.subn(lambda m: THREAD_NEW, source, count=1)
        log.append(f"部署线程替换 {n}")
    else:
        log.append("部署线程已是显式回报")

    # 3) 闸门调用：基线的 join 块，或旧接线的两参数 await。
    if "deployGate.await(deploy)" not in source:
        source, n = GATE_JOIN_RE.subn(lambda m: GATE_NEW, source, count=1)
        log.append(f"闸门（基线）替换 {n}")
        if n == 0:
            source, n = GATE_TWO_ARG_RE.subn(lambda m: GATE_NEW, source, count=1)
            log.append(f"闸门（旧接线）替换 {n}")
    else:
        log.append("闸门已是 deployGate.await")

    # 4) 其余小改动（精确字符串，已改过的跳过）。
    for label, needles, replacement in STR_CHANGES:
        if replacement and replacement in source:
            log.append(f"{label}: 已应用")
            continue
        hit = next((n for n in needles if source.count(n) == 1), None)
        if hit is not None:
            source = source.replace(hit, replacement)
            log.append(f"{label}: 已替换")
            continue
        if not replacement:
            log.append(f"{label}: 无需")
            continue
        log.append(f"{label}: 锚点命中 {[source.count(n) for n in needles]}")
        for line in log:
            print(line)
        print(f"::error::{label} 无法定位")
        return 1

    for line in log:
        print(line)

    TARGET.write_text(source, encoding="utf-8")
    problems: list[str] = []
    if source.count("DEPLOY_TIMEOUT_MS") != 2:
        problems.append(f"DEPLOY_TIMEOUT_MS 出现 {source.count('DEPLOY_TIMEOUT_MS')} 次（应为 2）")
    if source.count("markCompleted") != 1:
        problems.append(f"markCompleted 出现 {source.count('markCompleted')} 次（应为 1）")
    for leftover in ("deployError", "containsSuccessMarker", "containsRetryMarker",
                     "pkill -f uaf_plant_replay", "killall uaf_plant_replay"):
        if source.count(leftover):
            problems.append(f"仍残留 {leftover}")

    if problems:
        for line in problems:
            print(f"::error::{line}")
        return 1
    print("clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
