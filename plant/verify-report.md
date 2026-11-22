# 验收结果

- commit: `2d59b18e`
- 接线: success
- 单测: success
- 编译: success

## 接线日志

```text
wired 11 sites
BootGuard.classify: 1
DeployGate:         3
DEPLOY_TIMEOUT_MS:  2
::warning::仍残留 pkill -f uaf_plant_replay x1
```

## 用例

```text
TEST-com.gkeyes.lhasa26.core.BootGuardTest.xml
tests="8" skipped="0" failures="0" errors="0"
TEST-com.gkeyes.lhasa26.core.DeployGateTest.xml
tests="6" skipped="0" failures="0" errors="0"
```

## 入口是否真的调用防护

```text
BootGuard.classify  x1
DeployGate           x2
DEPLOY_TIMEOUT_MS    x2
旧 pkill 路径       x1
```

## 日志尾部

```text
For more on this, please refer to https://docs.gradle.org/9.9.1/userguide/command_line_interface.html#sec:command_line_warnings in the Gradle documentation.

BUILD SUCCESSFUL in 1m 44s
37 actionable tasks: 37 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.9.1/userguide/configuration_cache_enabling.html
To honour the JVM settings for this build a single-use Daemon process will be forked. For more on this, please refer to https://docs.gradle.org/9.9.1/userguide/gradle_daemon.html#sec:disabling_the_daemon in the Gradle documentation.
Daemon will be stopped at the end of the build 
> Task :app:preBuild UP-TO-DATE
> Task :app:preReleaseBuild UP-TO-DATE
> Task :app:generateReleaseResources
> Task :app:packageReleaseResources
> Task :design:miuix-console:ui:preBuild UP-TO-DATE
> Task :design:miuix-console:ui:preReleaseBuild UP-TO-DATE
> Task :design:miuix-console:ui:processReleaseNavigationResources
> Task :app:processReleaseNavigationResources
> Task :design:miuix-console:ui:generateReleaseResources
> Task :design:miuix-console:ui:packageReleaseResources
> Task :design:miuix-console:ui:parseReleaseLocalResources
> Task :app:parseReleaseLocalResources
> Task :design:miuix-console:ui:generateReleaseRFile
> Task :app:generateReleaseRFile
> Task :design:miuix-console:ui:javaPreCompileRelease
> Task :app:javaPreCompileRelease
> Task :design:miuix-console:ui:compileReleaseKotlin
> Task :design:miuix-console:ui:compileReleaseJavaWithJavac NO-SOURCE
> Task :design:miuix-console:ui:bundleLibCompileToJarRelease
> Task :app:compileReleaseKotlin NO-SOURCE
> Task :app:compileReleaseJavaWithJavac

[Incubating] Problems report is available at: file:///home/runner/work/Lhasa26-Android/Lhasa26-Android/build/reports/problems/problems-report.html

Deprecated Gradle features were used in this build, making it incompatible with Gradle 10.

You can use '--warning-mode all' to show the individual deprecation warnings and determine if they come from your own scripts or plugins.

For more on this, please refer to https://docs.gradle.org/9.9.1/userguide/command_line_interface.html#sec:command_line_warnings in the Gradle documentation.

BUILD SUCCESSFUL in 23s
15 actionable tasks: 15 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.9.1/userguide/configuration_cache_enabling.html
```
