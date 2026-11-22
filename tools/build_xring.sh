#!/usr/bin/env bash
# 从上游（MIT）源码构建 slide_probe、pc98260-su 与 uaf_plant_replay。
#
# 用法：tools/build_xring.sh <输出目录>
#
# 关键：不用上游的 src/xr98260_profiles.c（它只认作者手上那两条内核），
# 而是先用 tools/gen_xr_profiles.py 从 app/src/main/assets/lhasa_profile.txt
# 生成本机支持的 profile 表，再和开源码一起编译。这样产物与原件
# （读同一份 profile 文件）行为一致，OTA 换内核只需改文件里的一行。
#
# 编译选项与自有产物一致：-s 去符号、--gc-sections 砍死代码、关 unwind 表。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK="$ROOT/tools/xring.lock.properties"
OUT="${1:-$ROOT/build/xring}"
CACHE="${XRING_CACHE:-$ROOT/.gradle/xring-cache}"
PROFILE="$ROOT/app/src/main/assets/lhasa_profile.txt"

[ -f "$LOCK" ] || { echo "缺少 $LOCK" >&2; exit 1; }
[ -f "$PROFILE" ] || { echo "缺少 $PROFILE" >&2; exit 1; }
get() { sed -n "s/^$1=//p" "$LOCK" | head -1; }

COMMIT=$(get commit)
URL=$(get url)
SIZE=$(get size)
SHA=$(get sha256)
[ -n "$URL" ] && [ -n "$SHA" ] || { echo "锁文件字段不全" >&2; exit 1; }

mkdir -p "$CACHE" "$OUT"
TAR="$CACHE/xring-$COMMIT.tar.gz"

if [ -f "$TAR" ] && [ "$(wc -c < "$TAR" | tr -d ' ')" = "$SIZE" ] \
   && [ "$(sha256sum "$TAR" | cut -d' ' -f1)" = "$SHA" ]; then
  echo "使用缓存 $TAR"
else
  echo "下载 $URL"
  curl -fsSL --retry 3 -o "$TAR.part" "$URL"
  actual=$(sha256sum "$TAR.part" | cut -d' ' -f1)
  if [ "$actual" != "$SHA" ]; then
    rm -f "$TAR.part"
    echo "tarball 哈希不符：$actual != $SHA" >&2
    exit 1
  fi
  mv -f "$TAR.part" "$TAR"
fi

SRC="$CACHE/src-$COMMIT"
if [ ! -d "$SRC" ]; then
  rm -rf "$SRC.tmp"
  mkdir -p "$SRC.tmp"
  tar -xzf "$TAR" -C "$SRC.tmp" --strip-components=1
  mv "$SRC.tmp" "$SRC"
fi
echo "源码目录 $SRC"

# 生成的 profile 表放到源码目录旁边，头文件按相对路径引用
GEN="$CACHE/gen-$COMMIT"
mkdir -p "$GEN"
cp "$SRC/src/xr98260_profiles.h" "$GEN/"
python3 "$ROOT/tools/gen_xr_profiles.py" "$PROFILE" "$GEN/xr98260_profiles.c"

CFLAGS=(-target aarch64-linux-musl -std=gnu11 -O2 -static -s -pthread
        -ffunction-sections -fdata-sections -Wl,--gc-sections
        -fno-asynchronous-unwind-tables -fno-unwind-tables
        -I"$GEN")

echo "== slide_probe（tracefs 二进制记录扫描）"
zig cc "${CFLAGS[@]}" \
  "$GEN/xr98260_profiles.c" \
  "$SRC/src/xr98260_slide_probe.c" \
  -o "$OUT/slide_probe"

echo "== pc98260-su（uint32 长度前缀协议）"
zig cc "${CFLAGS[@]}" \
  "$SRC/src/pc98260_su.c" \
  -o "$OUT/pc98260-su"

echo "== uaf_plant_replay（早期单文件变体，CLI 与 App 现有调用一致）"
zig cc "${CFLAGS[@]}" \
  "$SRC/src/exploit-android-perf.c" \
  "$GEN/xr98260_profiles.c" \
  -o "$OUT/uaf_plant_replay"

ls -l "$OUT"/
sha256sum "$OUT"/*
