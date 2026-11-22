#!/usr/bin/env bash
# 全流程检查。顺序刻意排成：plant 交叉编译 -> 接线 -> 单测 -> 编译。
# plant 不需要 Android SDK，几十秒内就能给出“源码能不能替掉二进制”的结论，
# 放在最前面，即使后面的 Java 阶段挂掉，这一份证据也已经落到分支上了。
# 每一步结束都提交一次，不依赖 GitHub 的日志页面。
set +e
cd "$(dirname "$0")/.." || exit 1

WIRE=skipped
TEST=skipped
COMPILE=skipped
PLANT=skipped
COMMIT_CODE=0

commit_now() {
  git config user.name "lhasa-ci"
  git config user.email "lhasa-ci@users.noreply.github.com"
  [ "$COMMIT_CODE" = "1" ] && git add -A app 2>/dev/null
  git add plant/*.md plant/*.log plant/*.txt 2>/dev/null
  if git diff --cached --quiet; then
    return 0
  fi
  git commit -m "$1" >/dev/null 2>&1
  git push >/dev/null 2>&1 || echo "::warning::git push 失败"
}

heartbeat() {
  mkdir -p plant
  printf '%s stage=%s sha=%s\n' "$(date -u +%H:%M:%S)" "$1" "${GITHUB_SHA:0:8}" >> plant/heartbeat.log
  commit_now "ci: heartbeat $1 [verify]"
}

finish() {
  local tag
  if [ "$TEST" = success ] && [ "$COMPILE" = success ] && [ "$WIRE" = success ]; then
    tag="verify-ok-${GITHUB_SHA:0:8}"
  else
    tag="verify-fail-${GITHUB_SHA:0:8}"
  fi
  git ls-remote --tags origin 2>/dev/null | awk '{print $2}' | grep -v '\^{}' \
    | grep -E '^refs/tags/verify-' \
    | while read -r ref; do git push origin ":$ref" >/dev/null 2>&1; done
  git tag -f "$tag" >/dev/null 2>&1
  git push origin "refs/tags/$tag" --force >/dev/null 2>&1
  echo "tag=$tag"
}
trap finish EXIT

heartbeat start

# ---------- 1. plant 交叉编译 ----------
mkdir -p plant/out
: > plant/build.log
if ! command -v zig >/dev/null 2>&1; then
  if [ ! -x /tmp/zig-linux-x86_64-0.13.0/zig ]; then
    echo "downloading zig" >> plant/build.log
    timeout 300 curl -fsSL -o /tmp/zig.tar.xz \
      https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz >> plant/build.log 2>&1
    tar -xf /tmp/zig.tar.xz -C /tmp >> plant/build.log 2>&1
  fi
  export PATH="/tmp/zig-linux-x86_64-0.13.0:$PATH"
fi
heartbeat zig-ready

echo "zig=$(command -v zig || echo MISSING)" >> plant/build.log
if [ -z "$(command -v zig)" ]; then
  echo "FAILED zig 不可用" >> plant/build.log
  PLANT=failure
else
  failed=0
  built=0
  for src in plant/*.c; do
    [ -e "$src" ] || continue
    out="plant/out/$(basename "${src%.c}")"
    echo "== zig cc $src -> $out" >> plant/build.log
    if timeout 180 zig cc -target aarch64-linux-musl -O2 -static -pthread "$src" -o "$out" >> plant/build.log 2>&1; then
      built=$((built + 1))
      file "$out" >> plant/build.log 2>&1
    else
      failed=$((failed + 1))
      echo "FAILED $src" >> plant/build.log
    fi
  done
  echo "built=$built failed=$failed" >> plant/build.log
  ls -l plant/out 2>&1 >> plant/build.log
  if [ "$failed" -eq 0 ] && [ "$built" -gt 0 ]; then PLANT=success; else PLANT=failure; fi
fi

{
  echo "# plant 源码可替换性验证"
  echo
  echo "- commit: \`${GITHUB_SHA:0:8}\`"
  echo "- 结果: **${PLANT}**"
  echo "- 方法: zig cc -target aarch64-linux-musl -O2 -static -pthread"
  echo
  echo "## 编译日志"
  echo
  echo '```text'
  cat plant/build.log
  echo '```'
} > plant/build-status.md
heartbeat plant-done

# ---------- 2. 接线 ----------
python3 tools/wire_workflow.py > wire.log 2>&1
if [ $? -eq 0 ]; then WIRE=success; else WIRE=failure; fi
echo "WIRE=$WIRE"
heartbeat wired

# ---------- 3. 单测 ----------
for root in "${ANDROID_SDK_ROOT:-}" /usr/local/lib/android/sdk /opt/android-sdk; do
  if [ -n "$root" ] && [ -d "$root/platforms" ]; then
    export ANDROID_SDK_ROOT="$root"
    break
  fi
done
chmod +x gradlew 2>/dev/null
timeout 900 ./gradlew --no-daemon :app:testDebugUnitTest > test.log 2>&1
if [ $? -eq 0 ]; then TEST=success; else TEST=failure; fi
heartbeat tested

# ---------- 4. 编译 ----------
timeout 900 ./gradlew --no-daemon :app:compileReleaseJavaWithJavac >> test.log 2>&1
if [ $? -eq 0 ]; then COMPILE=success; else COMPILE=failure; fi

if [ "$WIRE" = success ] && [ "$TEST" = success ] && [ "$COMPILE" = success ]; then
  COMMIT_CODE=1
fi

{
  echo "# 验收结果"
  echo
  echo "- commit: \`${GITHUB_SHA:0:8}\`"
  echo "- plant: ${PLANT}"
  echo "- 接线: ${WIRE}"
  echo "- 单测: ${TEST}"
  echo "- 编译: ${COMPILE}"
  echo "- 回写源码: ${COMMIT_CODE}"
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
  echo "## 接线日志"
  echo
  echo '```text'
  tail -n 20 wire.log 2>/dev/null
  echo '```'
  echo
  echo "## 入口调用"
  echo
  echo '```text'
  wf=app/src/main/java/com/gkeyes/lhasa26/core/WorkflowEngine.java
  echo "BootGuard.classify x$(grep -c 'BootGuard.classify' "$wf" 2>/dev/null || echo 0)"
  echo "markCompleted      x$(grep -c 'markCompleted' "$wf" 2>/dev/null || echo 0)"
  echo "deployError        x$(grep -c 'deployError' "$wf" 2>/dev/null || echo 0)"
  echo '```'
  echo
  echo "## 测试日志尾部"
  echo
  echo '```text'
  tail -n 20 test.log 2>/dev/null
  echo '```'
} > plant/verify-report.md
heartbeat report

if [ "$COMMIT_CODE" = "1" ] && [ "$PLANT" = success ]; then
  exit 0
fi
exit 1
