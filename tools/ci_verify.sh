#!/usr/bin/env bash
# 只读校验 + 一次性固化。
#
# 本轮之前 CI 每轮都改源码，导致验收无法绑定到提交（审计 P1）。
# 现在只做一件事：把接线结果**固化成一个真实提交**，同时删掉改写脚本，
# 之后仓库里再没有“CI 改源码”这个环节。
set +e
cd "$(dirname "$0")/.." || exit 1

BRANCH="${GITHUB_REF_NAME:-fix/p0-clean-boot-retry}"
WIRE=n/a
TEST=skipped
BUILD=skipped
FROZEN=no

push_with_retry() {
  local i
  for i in 1 2 3 4 5 6; do
    git pull --rebase --autostash origin "$BRANCH" >/dev/null 2>&1
    if git push origin "HEAD:$BRANCH" >/dev/null 2>&1; then return 0; fi
    sleep 4
  done
  echo "::warning::push 重试 6 次仍失败"
  return 1
}

for root in "${ANDROID_SDK_ROOT:-}" /usr/local/lib/android/sdk /opt/android-sdk; do
  if [ -n "$root" ] && [ -d "$root/platforms" ]; then
    export ANDROID_SDK_ROOT="$root"
    break
  fi
done

if [ -f tools/wire_workflow.py ]; then
  python3 tools/wire_workflow.py > wire.log 2>&1
  if [ $? -eq 0 ]; then WIRE=success; else WIRE=failure; fi
  tail -n 20 wire.log
else
  echo "改写脚本已移除，源码即事实"
fi

chmod +x gradlew 2>/dev/null
timeout 1200 ./gradlew --no-daemon :app:testDebugUnitTest > test.log 2>&1
if [ $? -eq 0 ]; then TEST=success; else TEST=failure; fi

timeout 1800 ./gradlew --no-daemon :app:assembleDebug >> build.log 2>&1
if [ $? -eq 0 ]; then BUILD=success; else BUILD=failure; fi

APK=$(ls app/build/outputs/apk/debug/*.apk 2>/dev/null | head -1)
APK_SIZE=$([ -n "$APK" ] && du -h "$APK" | cut -f1 || echo "-")

# 全绿才固化：一次性把接线结果和脚本删除放进同一个提交。
if [ "$WIRE" = success ] && [ "$TEST" = success ] && [ "$BUILD" = success ] && [ -n "$APK" ]; then
  git config user.name "lhasa-ci"
  git config user.email "lhasa-ci@users.noreply.github.com"
  git add -A app 2>/dev/null
  git rm -q tools/wire_workflow.py 2>/dev/null
  if ! git diff --cached --quiet; then
    git commit -m "fix(workflow): 固化接线结果并移除源码改写脚本

CI 实测通过，把改写后的 WorkflowEngine 作为普通提交固定下来，
同时删除 tools/wire_workflow.py。此后 CI 只做只读校验，
验收可以绑定到具体提交。" >/dev/null 2>&1
    push_with_retry && FROZEN=yes
  fi
fi

{
  echo "# 构建与验收"
  echo
  echo "- commit: \`${GITHUB_SHA:0:8}\`"
  echo "- 接线: ${WIRE}"
  echo "- 单测: ${TEST}"
  echo "- 构建: ${BUILD}"
  echo "- APK: ${APK:-缺失} (${APK_SIZE})"
  echo "- 已固化: ${FROZEN}"
  echo
  echo "## 用例"
  echo
  echo '```text'
  for f in app/build/test-results/testDebugUnitTest/*.xml; do
    [ -f "$f" ] || continue
    basename "$f"
    grep -o 'tests="[0-9]*" skipped="[0-9]*" failures="[0-9]*" errors="[0-9]*"' "$f" | head -1
  done
  echo '```'
  echo
  echo "## 入口调用"
  echo
  echo '```text'
  wf=app/src/main/java/com/gkeyes/lhasa26/core/WorkflowEngine.java
  echo "BootGuard.classify x$(grep -c 'BootGuard.classify' "$wf" 2>/dev/null || echo 0)"
  echo "markCompleted      x$(grep -c 'markCompleted' "$wf" 2>/dev/null || echo 0)"
  echo "DEPLOY_TIMEOUT_MS  声明 x$(grep -c 'private static final long DEPLOY_TIMEOUT_MS' "$wf" 2>/dev/null || echo 0)"
  echo "deployError        x$(grep -c 'deployError' "$wf" 2>/dev/null || echo 0)"
  echo '```'
  echo
  echo "## 失败信息"
  echo
  echo '```text'
  grep -E 'error:|FAILED|BUILD FAILED|What went wrong' test.log build.log 2>/dev/null | head -20
  echo '```'
} > plant/verify-report.md

consolidate() {
  git config user.name "lhasa-ci"
  git config user.email "lhasa-ci@users.noreply.github.com"
  git add plant/verify-report.md 2>/dev/null
  if git diff --cached --quiet; then return 0; fi
  git commit -m "ci: 验收 ${GITHUB_SHA:0:8} test=${TEST} build=${BUILD} apk=$([ -n "$APK" ] && echo yes || echo no) [verify]" >/dev/null 2>&1
  push_with_retry
}
consolidate

[ "$TEST" = success ] && [ "$BUILD" = success ] && [ -n "$APK" ] && exit 0
exit 1
