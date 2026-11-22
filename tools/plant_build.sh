#!/usr/bin/env bash
# plant 交叉编译验证：只证明“五个 payload 的源码在本仓库内可重复构建”。
# 不跑测试、不碰 app/，所以它永远不会和主构建抢同一个分支。
set +e
cd "$(dirname "$0")/.." || exit 1

BRANCH="${GITHUB_REF_NAME:-fix/p0-clean-boot-retry}"
mkdir -p plant/out
: > plant/build.log

if ! command -v zig >/dev/null 2>&1; then
  if [ ! -x /tmp/zig-linux-x86_64-0.13.0/zig ]; then
    timeout 300 curl -fsSL -o /tmp/zig.tar.xz \
      https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz >> plant/build.log 2>&1
    tar -xf /tmp/zig.tar.xz -C /tmp >> plant/build.log 2>&1
  fi
  export PATH="/tmp/zig-linux-x86_64-0.13.0:$PATH"
fi

echo "zig=$(command -v zig || echo MISSING)" >> plant/build.log
failed=0
built=0
for src in plant/*.c; do
  [ -e "$src" ] || continue
  out="plant/out/$(basename "${src%.c}")"
  echo "== zig cc $src" >> plant/build.log
  if timeout 180 zig cc -target aarch64-linux-musl -O2 -static -pthread "$src" -o "$out" >> plant/build.log 2>&1; then
    built=$((built + 1))
    file "$out" >> plant/build.log 2>&1
  else
    failed=$((failed + 1))
    echo "FAILED $src" >> plant/build.log
  fi
done
echo "built=$built failed=$failed" >> plant/build.log
ls -l plant/out >> plant/build.log 2>&1

exit $([ "$failed" -eq 0 ] && [ "$built" -gt 0 ] && echo 0 || echo 1)
