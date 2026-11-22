#!/usr/bin/env bash
# CI 全部检查：接线、单测、release 编译、plant 交叉编译。
#
# 设计原则：流程写在一个脚本里，每完成一项立刻 flush 一份报告并提交。
# 之前把流程拆成多个 step，任何一步提前失败（或 YAML 解析失败）都不会留下任何证据，
# 只能看到“verify-fail”而不知道为什么。
set +e
cd "$(dirname "$0")/.." || exit 1

WIRE=skipped
TEST=skipped
COMPILE=skipped
PLANT=skipped

flush() {
  {
    echo "# 验收结果"
    echo
    echo "- commit: \`${GITHUB_SHA:0:8}\`"
    echo "- 接线: ${WIRE}"
    echo "- 单测: ${TEST}"
    echo "- 编译: ${COMPILE}"
    echo "- plant: ${PLANT}"
    echo
    echo "## 接线日志"
    echo
    echo '```text'
    tail -n 30 wire.log 2>/dev/null
    echo '```'
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
    echo "## 入口调用情况"
    echo
    echo '```text'
    wf=app/src/main/java/com/gkeyes/lhasa26/core/WorkflowEngine.java
    echo "BootGuard.classify x$(grep -c 'BootGuard.classify' "$wf" 2>/dev/null || echo 0)"
    echo "DeployGate         x$(grep -c 'DeployGate' "$wf" 2>/dev/null || echo 0)"
    echo "旧 pkill 路径     x$(grep -c 'pkill -f uaf_plant_replay' "$wf" 2>/dev/null || echo 0)"
    echo '```'
    echo
    echo "## plant 编译"
    echo
    echo '```text'
    tail -n 40 plant/build.log 2>/dev/null
    echo '```'
    echo
    echo "## 测试日志尾部"
    echo
    echo '```text'
    tail -n 25 test.log 2>/dev/null
    echo '```'
  } > plant/verify-report.md

  git config user.name "lhasa-ci"
  git config user.email "lhasa-ci@users.noreply.github.com"
  git add -A app 2>/dev/null
  git add plant/verify-report.md plant/build.log plant/audit.log 2>/dev/null
  if git diff --cached --quiet; then
    echo "report unchanged"
  else
    git commit -m "verify: wire=${WIRE} test=${TEST} compile=${COMPILE} plant=${PLANT} [verify]" >/dev/null 2>&1
    git push >/dev/null 2>&1 || echo "::warning::git push 失败，报告只在运行器上"
  fi
}

finish() {
  flush
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

for root in "${ANDROID_SDK_ROOT:-}" /usr/local/lib/android/sdk /opt/android-sdk; do
  if [ -n "$root" ] && [ -d "$root/platforms" ]; then
    export ANDROID_SDK_ROOT="$root"
    echo "sdk=$ANDROID_SDK_ROOT"
    break
  fi
done

python3 tools/wire_workflow.py > wire.log 2>&1
if [ $? -eq 0 ]; then WIRE=success; else WIRE=failure; fi
flush

test -x gradlew || chmod +x gradlew
./gradlew --no-daemon :app:testDebugUnitTest > test.log 2>&1
if [ $? -eq 0 ]; then TEST=success; else TEST=failure; fi
flush

./gradlew --no-daemon :app:compileReleaseJavaWithJavac >> test.log 2>&1
if [ $? -eq 0 ]; then COMPILE=success; else COMPILE=failure; fi
flush

mkdir -p plant/out
: > plant/build.log
if ! command -v zig >/dev/null 2>&1; then
  if [ ! -d /tmp/zig-linux-x86_64-0.13.0 ]; then
    curl -fsSL -o /tmp/zig.tar.xz https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz >> plant/build.log 2>&1
    tar -xf /tmp/zig.tar.xz -C /tmp >> plant/build.log 2>&1
  fi
  export PATH="/tmp/zig-linux-x86_64-0.13.0:$PATH"
fi

{
  echo "zig=$(command -v zig || echo missing)"
  python3 - <<'PY'
import pathlib

def has_elf(head: bytes) -> bool:
    return head[:4] == b"\x7fELF"

assets = pathlib.Path("app/src/main/assets")
sources = {p.name[:-2] for p in pathlib.Path("plant").glob("*.c")}
missing = []
for path in sorted(assets.iterdir()):
    if not path.is_file():
        continue
    with path.open("rb") as fh:
        if not has_elf(fh.read(4)):
            continue
    ok = path.name in sources
    if not ok:
        missing.append(path.name)
    print(f"{'OK' if ok else 'MISSING':8} {path.name:22} {path.stat().st_size:>10}  {path.name + '.c' if ok else '-'}")
print(f"合计 {len(missing)} 个资产尚无源码")
PY
} >> plant/build.log 2>&1
tee plant/audit.log < plant/build.log >/dev/null

failed=0
for src in plant/*.c; do
  [ -e "$src" ] || continue
  out="plant/out/$(basename "${src%.c}")"
  echo "== zig cc $src -> $out" >> plant/build.log
  if zig cc -target aarch64-linux-musl -O2 -static -pthread "$src" -o "$out" >> plant/build.log 2>&1; then
    file "$out" >> plant/build.log
  else
    echo "FAILED $src" >> plant/build.log
    failed=1
  fi
done
ls -l plant/out >> plant/build.log 2>&1
if [ "$failed" -eq 0 ] && ls plant/out/* >/dev/null 2>&1; then PLANT=success; else PLANT=failure; fi
echo "PLANT=$PLANT"
flush

if [ "$WIRE" = success ] && [ "$TEST" = success ] && [ "$COMPILE" = success ] && [ "$PLANT" = success ]; then
  exit 0
fi
exit 1
