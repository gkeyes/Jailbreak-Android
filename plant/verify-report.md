# 验收结果

- commit: `a2f31d5b`
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
常量已存在
部署线程替换 1
闸门（基线）替换 0
闸门（旧接线）替换 1
内核不匹配警告: 已应用
runPayload 调用点: 已应用
runPayload 签名: 已应用
payload 启动命令: 已应用
成功标记判定: 已应用
重试标记判定: 已应用
stopPayload 改为进程组信号: 已应用
cleanupBinaries 也改用进程组信号: 已应用
payloadProcessCount 改用 kill -0: 已应用
::error::DEPLOY_TIMEOUT_MS 出现 3 次（应为 2）
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
* What went wrong:
Execution failed for task ':app:compileReleaseJavaWithJavac' (registered by plugin 'com.android.internal.application').
> Compilation failed; see the compiler output below.
  /home/runner/work/Lhasa26-Android/Lhasa26-Android/app/src/main/java/com/gkeyes/lhasa26/core/WorkflowEngine.java:28: error: variable DEPLOY_TIMEOUT_MS is already defined in class WorkflowEngine
      private static final long DEPLOY_TIMEOUT_MS = 8000L;
                                ^
  1 error

* Try:
> Check your code and dependencies to fix the compilation error(s)
> Run with --scan to get full insights from a Build Scan (powered by Develocity).

Deprecated Gradle features were used in this build, making it incompatible with Gradle 10.

You can use '--warning-mode all' to show the individual deprecation warnings and determine if they come from your own scripts or plugins.

For more on this, please refer to https://docs.gradle.org/9.9.1/userguide/command_line_interface.html#sec:command_line_warnings in the Gradle documentation.

BUILD FAILED in 28s
15 actionable tasks: 15 executed
```
