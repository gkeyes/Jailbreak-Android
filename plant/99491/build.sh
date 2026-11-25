#!/usr/bin/env bash
# 交叉编译 CVE-2026-99491 real_cred 链（plant/99491/exp.c）。
#
# 构建前先用 tools/99491/gen_profile.py 从唯一事实源
# app/src/main/assets/lhasa_99491_profile.json 重新生成 plant/99491/profile.h
# （fail-closed：JSON 校验不过就停，不会编译出未标定的二进制）。
#
# 编译器优先级：
#   1. zig cc -target aarch64-linux-musl -O2 -static -s   （CI，静态 musl）
#   2. aarch64-linux-gnu-gcc -O2 -static -s               （本机 proot，静态 glibc）
#
# 用法：
#   bash plant/99491/build.sh                 # 校验+生成 profile.h，再编译
#   bash plant/99491/build.sh --self-test    # 编译后跑 exp --self-test / --help（仅 aarch64 主机）
#   bash plant/99491/build.sh --check        # 只跑 gen_profile.py --check
#   bash plant/99491/build.sh --json PATH --out DIR
#   bash plant/99491/build.sh --src plant/99491/exp_direct.c   # 显式指定源码（沙箱故障恢复期用）
#   PROFILE_JSON=... bash plant/99491/build.sh
#
# 产物：<out>/exp（默认 build/99491/exp），打印大小与 sha256。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/build/99491"
JSON="${PROFILE_JSON:-$ROOT/app/src/main/assets/lhasa_99491_profile.json}"
GEN_ONLY=0
SELF_TEST=0
SRC_OVERRIDE=""

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --json) JSON="${2:?--json 需要路径}"; shift 2 ;;
        --out) OUT="${2:?--out 需要目录}"; shift 2 ;;
        --check) GEN_ONLY=1; shift ;;
        --self-test) SELF_TEST=1; shift ;;
        --src) SRC_OVERRIDE="${2:?--src 需要路径}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数：$1（-h 查看用法）" >&2; exit 2 ;;
    esac
done

echo "== 1/4 生成并校验 profile (gen_profile.py)"
if [ ! -f "$JSON" ]; then
    echo "缺少 profile JSON：$JSON" >&2
    echo "真实标定值由 Lead 提供；自检占位 profile 用：" >&2
    echo "  bash plant/99491/build.sh --json plant/99491/example-profile.json" >&2
    echo "（占位 profile 的 release 不在参考表里，需要 gen_profile.py 的" >&2
    echo "  --allow-unknown-release；CI/发布路径必须用真实 JSON）" >&2
    exit 1
fi
if [ "$JSON" = "$ROOT/app/src/main/assets/lhasa_99491_profile.json" ]; then
    python3 "$ROOT/tools/99491/gen_profile.py" --check --gen --json "$JSON"
else
    python3 "$ROOT/tools/99491/gen_profile.py" --check --gen --json "$JSON" \
        --allow-unknown-release --allow-unverified
fi
if [ "$GEN_ONLY" = 1 ]; then
    echo "== --check：profile 校验通过，未编译"
    exit 0
fi

echo "== 2/4 选择交叉编译器"
CFLAGS=(-std=gnu11 -O2 -static -s -pthread
        -ffunction-sections -fdata-sections -Wl,--gc-sections
        -fno-asynchronous-unwind-tables -fno-unwind-tables
        -I"$ROOT/plant/99491")
if command -v zig >/dev/null 2>&1; then
    CC=(zig cc -target aarch64-linux-musl)
    echo "   zig: $(zig version)（musl 静态）"
elif command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    CC=(aarch64-linux-gnu-gcc)
    echo "   gcc: $(aarch64-linux-gnu-gcc --version | head -1)（glibc 静态）"
else
    echo "没有 zig，也没有 aarch64-linux-gnu-gcc。" >&2
    echo "CI 用 zig 0.13；本机装 cross gcc 即可回退。" >&2
    exit 1
fi

echo "== 3/4 编译"
mkdir -p "$OUT"
SRC="$ROOT/plant/99491/exp.c"
[ -r "$SRC" ] || SRC="$ROOT/plant/99491/exp_direct.c"
if [ -n "$SRC_OVERRIDE" ]; then
    SRC="$SRC_OVERRIDE"
fi
echo "源码：$SRC"
"${CC[@]}" "${CFLAGS[@]}" "$SRC" -o "$OUT/exp"
chmod 755 "$OUT/exp"
ls -l "$OUT/exp"
sha256sum "$OUT/exp"

echo "== 4/4 构建自检"
if [ "$SELF_TEST" = 1 ]; then
    host=$(uname -m)
    case "$host" in
        aarch64|arm64)
            echo "-- exp --self-test"
            "$OUT/exp" --self-test
            echo "-- exp --help（截取前 8 行）"
            "$OUT/exp" --help | head -8
            ;;
        *)
            echo "主机是 $host，aarch64 静态 ELF 不能本机执行；--self-test 跳过"
            echo "（真机/CI 上再跑：$OUT/exp --self-test）"
            ;;
    esac
else
    echo "（未传 --self-test；产物只做大小/sha256 自检）"
fi
echo "OK $OUT/exp"
