# 验收结果

- commit: `5ec703d2`
- plant: success
- 接线: failure
- 单测: failure
- 编译: failure
- 回写源码: 0

## 用例

```text
```

## 接线日志

```text
::error::DEPLOY_TIMEOUT_MS 常量: 候选锚点命中次数 [0]，均不为 1
```

## 入口调用

```text
BootGuard.classify x1
markCompleted      x0
0
deployError        x3
```

## 测试日志尾部

```text
  /home/runner/work/Lhasa26-Android/Lhasa26-Android/app/src/main/java/com/gkeyes/lhasa26/core/WorkflowEngine.java:244: error: method await in class DeployGate cannot be applied to given types;
                  .await(deploy, deployError);
                  ^
    required: Thread
    found:    Thread,AtomicReference<Exception>
    reason: actual and formal argument lists differ in length
  2 errors

* Try:
> Check your code and dependencies to fix the compilation error(s)
> Run with --scan to get full insights from a Build Scan (powered by Develocity).

Deprecated Gradle features were used in this build, making it incompatible with Gradle 10.

You can use '--warning-mode all' to show the individual deprecation warnings and determine if they come from your own scripts or plugins.

For more on this, please refer to https://docs.gradle.org/9.9.1/userguide/command_line_interface.html#sec:command_line_warnings in the Gradle documentation.

BUILD FAILED in 35s
15 actionable tasks: 15 executed
```
