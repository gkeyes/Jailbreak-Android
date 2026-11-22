# 验收结果

- commit: `5f7810ee`
- plant: success
- 接线: success
- 单测: failure
- 编译: failure
- 回写源码: 0

## 用例

```text
```

## 接线日志

```text
applied=3 skipped=10
BootGuard.classify: 1
DeployGate:         4
markCompleted:      1
DEPLOY_TIMEOUT_MS:  4
no leftovers
```

## 入口调用

```text
BootGuard.classify x1
markCompleted      x1
deployError        x0
0
```

## 测试日志尾部

```text
  /home/runner/work/Lhasa26-Android/Lhasa26-Android/app/src/main/java/com/gkeyes/lhasa26/core/WorkflowEngine.java:28: error: variable DEPLOY_TIMEOUT_MS is already defined in class WorkflowEngine
      private static final long DEPLOY_TIMEOUT_MS = 8000L;
                                ^
  /home/runner/work/Lhasa26-Android/Lhasa26-Android/app/src/main/java/com/gkeyes/lhasa26/core/WorkflowEngine.java:29: error: variable DEPLOY_TIMEOUT_MS is already defined in class WorkflowEngine
      private static final long DEPLOY_TIMEOUT_MS = 8000L;
                                ^
  2 errors

* Try:
> Check your code and dependencies to fix the compilation error(s)
> Run with --scan to get full insights from a Build Scan (powered by Develocity).

Deprecated Gradle features were used in this build, making it incompatible with Gradle 10.

You can use '--warning-mode all' to show the individual deprecation warnings and determine if they come from your own scripts or plugins.

For more on this, please refer to https://docs.gradle.org/9.9.1/userguide/command_line_interface.html#sec:command_line_warnings in the Gradle documentation.

BUILD FAILED in 26s
15 actionable tasks: 15 executed
```
