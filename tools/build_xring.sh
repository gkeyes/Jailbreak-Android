#!/usr/bin/env bash
# 从上游（MIT）源码构建 slide_probe、pc98260-su 与 uaf_plant_replay。
#
# 用法：tools/build_xring.sh <输出目录>
#
# 流程：按 tools/xring.lock.properties 下载 tarball → 校验 sha256 → 解包 →
#       用 zig cc 交叉编译 → 产物写到 <输出目录>/。
#
# 只做本地编译，不接触设备。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK="$ROOT/tools/xring.lock.properties"
OUT="${1:-$ROOT/build/xring}"
CACHE="${XRING_CACHE:-$ROOT/.gradle/xring-cache}"

[ -f "$LOCK" ] || { echo "缺少 $LOCK" >&2; exit 1; }
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

CFLAGS=(-target aarch64-linux-musl -std=gnu11 -O2 -static -pthread
        -ffunction-sections -fdata-sections -Wl,--gc-sections)

echo "== slide_probe（tracefs 二进制记录扫描）"
zig cc "${CFLAGS[@]}" \
  "$SRC/src/xr98260_profiles.c" \
  "$SRC/src/xr98260_slide_probe.c" \
  -o "$OUT/slide_probe"

echo "== pc98260-su（uint32 长度前缀协议）"
zig cc "${CFLAGS[@]}" \
  "$SRC/src/pc98260_su.c" \
  -o "$OUT/pc98260-su"

echo "== uaf_plant_replay（早期单文件变体，CLI 与 App 现有调用一致）"
zig cc "${CFLAGS[@]}" \
  "$SRC/src/exploit-android-perf.c" \
  "$SRC/src/xr98260_profiles.c" \
  -o "$OUT/uaf_plant_replay"

ls -l "$OUT"/
sha256sum "$OUT"/*
