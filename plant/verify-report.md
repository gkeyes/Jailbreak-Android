# 构建与验收

- commit: `2eb4ae5c`
- 接线: n/a
- 单测: success
- 构建: success
- APK: app/build/outputs/apk/debug/app-debug.apk (43M)
- 已固化: no

## 用例

```text
TEST-com.gkeyes.lhasa26.core.BootGuardTest.xml
tests="8" skipped="0" failures="0" errors="0"
TEST-com.gkeyes.lhasa26.core.DeployGateTest.xml
tests="8" skipped="0" failures="0" errors="0"
```

## 入口调用

```text
BootGuard.classify x1
markCompleted      x1
DEPLOY_TIMEOUT_MS  声明 x1
deployError        x0
0
```

## 失败信息

```text
```
