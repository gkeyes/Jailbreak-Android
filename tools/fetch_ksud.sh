#!/usr/bin/env sh
# 拉取并校验 tools/ksud.lock.properties 锁定的上游 ksud。
#
# 用法：
#   tools/fetch_ksud.sh                 # 落到 app/src/main/assets/ksud
#   tools/fetch_ksud.sh /tmp/ksud       # 落到指定路径
#   KSUD_CACHE=/path tools/fetch_ksud.sh
#
# 行为：已存在且哈希匹配 → 直接复用（不联网）；不匹配 → 重新下载校验后原子替换。
# 任何一步校验失败都会退出非 0，并把旧文件留在原地。
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK="$ROOT/tools/ksud.lock.properties"
DEST="${1:-$ROOT/app/src/main/assets/ksud}"
CACHE="${KSUD_CACHE:-$ROOT/.gradle/ksud-cache}"

[ -f "$LOCK" ] || { echo "缺少 $LOCK" >&2; exit 1; }

get() { sed -n "s/^$1=//p" "$LOCK" | head -1; }
URL=$(get url); SIZE=$(get size); SHA=$(get sha256); TAG=$(get tag)
[ -n "$URL" ] && [ -n "$SIZE" ] && [ -n "$SHA" ] || { echo "锁文件字段不全" >&2; exit 1; }

sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else echo "没有可用的 sha256 工具" >&2; return 1; fi
}

verify() { # $1 = 文件
  [ -f "$1" ] || return 1
  actual_size=$(wc -c < "$1" | tr -d ' ')
  [ "$actual_size" = "$SIZE" ] || { echo "size 不匹配：$actual_size != $SIZE" >&2; return 1; }
  actual_sha=$(sha_of "$1")
  [ "$actual_sha" = "$SHA" ] || { echo "sha256 不匹配：$actual_sha != $SHA" >&2; return 1; }
  return 0
}

if verify "$DEST"; then
  echo "ksud 已就绪：$DEST ($TAG, sha256=$SHA)"
  exit 0
fi

mkdir -p "$CACHE"
CACHED="$CACHE/ksud-$TAG"
if ! verify "$CACHED"; then
  echo "下载 $URL"
  TMP="$CACHED.part"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$TMP" "$URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$TMP" "$URL"
  else
    echo "没有 curl/wget" >&2; exit 1
  fi
  if ! verify "$TMP"; then
    rm -f "$TMP"
    echo "下载产物校验失败，已丢弃" >&2
    exit 1
  fi
  mv -f "$TMP" "$CACHED"
fi

mkdir -p "$(dirname "$DEST")"
cp -f "$CACHED" "$DEST.new"
chmod 755 "$DEST.new" 2>/dev/null || true
mv -f "$DEST.new" "$DEST"
verify "$DEST"
echo "ksud 已安装：$DEST ($TAG, sha256=$SHA)"
