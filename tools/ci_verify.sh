#!/usr/bin/env bash
# 只读校验：资产台账 + 单测 + 组装 debug APK。
#
# 与旧版的区别（审计 P1：CI 往分支回推提交，导致验收无法绑定到具体 commit）：
#   - 不再 git commit / git push 任何东西；
#   - 不再改写源码（wire_workflow.py 的固化早已完成，脚本已删）；
#   - 报告写到 $RUNNER_TEMP，由 workflow 作为 Artifact 上传，与本次 SHA 绑定。
#
# 每一步都会打印自己的判定结果，最后再打印四行汇总——
# 之前出现过"两边都 BUILD SUCCESSFUL 但整体仍然红"的情况，
# 没有这层打印就只能靠猜。
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

OUT="${RUNNER_TEMP:-$(mktemp -d)}"
mkdir -p "$OUT"
LEDGER=failure
TEST=failure
BUILD=failure

echo "== 资产台账 =="
python3 tools/check_assets.py --strict 2>&1 | tee "$OUT/assets.log"
ledger_rc=${PIPESTATUS[0]}
[ "$ledger_rc" -eq 0 ] && LEDGER=success
echo "[判定] 台账 rc=${ledger_rc} → ${LEDGER}"

for root in "${ANDROID_SDK_ROOT:-}" /usr/local/lib/android/sdk /opt/android-sdk; do
  if [ -n "$root" ] && [ -d "$root/platforms" ]; then
    export ANDROID_SDK_ROOT="$root"
    break
  fi
done

chmod +x gradlew 2>/dev/null

echo "== 单测 =="
timeout 1200 ./gradlew --no-daemon :app:testDebugUnitTest > "$OUT/test.log" 2>&1
test_rc=$?
[ "$test_rc" -eq 0 ] && TEST=success
echo "[判定] 单测 rc=${test_rc} → ${TEST}"
tail -n 5 "$OUT/test.log"

echo "== 组装 =="
timeout 1800 ./gradlew --no-daemon :app:assembleDebug > "$OUT/build.log" 2>&1
build_rc=$?
[ "$build_rc" -eq 0 ] && BUILD=success
echo "[判定] 组装 rc=${build_rc} → ${BUILD}"
tail -n 5 "$OUT/build.log"

APK=$(ls app/build/outputs/apk/debug/*.apk 2>/dev/null | head -1)
APK_SIZE=$([ -n "$APK" ] && du -h "$APK" | cut -f1 || echo "-")
echo "[判定] APK 路径：${APK:-未找到}"
ls -la app/build/outputs/apk/debug/ 2>/dev/null | head -10 || echo "（目录不存在）"

{
  echo "# 构建与验收"
  echo
  echo "- commit: \`${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null | cut -c1-8)}\`"
  echo "- 资产台账: ${LEDGER}"
  echo "- 单测: ${TEST}"
  echo "- 构建: ${BUILD}"
  echo "- APK: ${APK:-缺失} (${APK_SIZE})"
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
  echo "## 失败信息"
  echo
  echo '```text'
  grep -E 'error:|FAILED|BUILD FAILED|What went wrong|FAIL ' "$OUT/test.log" "$OUT/build.log" "$OUT/assets.log" 2>/dev/null | head -30
  echo '```'
} > "$OUT/verify-report.md"

echo
echo "== 汇总 =="
echo "LEDGER=${LEDGER} TEST=${TEST} BUILD=${BUILD} APK=${APK:-none}"

if [ "$LEDGER" = success ] && [ "$TEST" = success ] && [ "$BUILD" = success ] && [ -n "$APK" ]; then
  echo "[结果] 通过"
  exit 0
fi

echo "[结果] 未通过：台账=${LEDGER} 单测=${TEST} 组装=${BUILD} APK=${APK:-none}"
exit 1
