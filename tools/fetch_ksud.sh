#!/usr/bin/env sh
# 拉取并校验 tools/ksud.lock.properties 锁定的上游 ksud。
#
# 上游产物是 KernelSU Manager APK 里的 lib/arm64-v8a/libksud.so，
# 所以要「下载 APK → 校验 APK → 抽出 entry → 校验 entry」两步都对得上才落盘。
#
# 用法：
#   tools/fetch_ksud.sh                 # 落到 app/src/main/assets/ksud
#   tools/fetch_ksud.sh /tmp/ksud       # 落到指定路径
#   KSUD_CACHE=/path tools/fetch_ksud.sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK="$ROOT/tools/ksud.lock.properties"
DEST="${1:-$ROOT/app/src/main/assets/ksud}"
CACHE="${KSUD_CACHE:-$ROOT/.gradle/ksud-cache}"

[ -f "$LOCK" ] || { echo "缺少 $LOCK" >&2; exit 1; }

get() { sed -n "s/^$1=//p" "$LOCK" | head -1; }
URL=$(get url); TAG=$(get tag); ENTRY=$(get entry)
APK_SHA=$(get apkSha256); SIZE=$(get size); SHA=$(get sha256)
[ -n "$URL" ] && [ -n "$SIZE" ] && [ -n "$SHA" ] && [ -n "$APK_SHA" ] \
  || { echo "锁文件字段不全" >&2; exit 1; }

sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else echo "没有可用的 sha256 工具" >&2; return 1; fi
}
size_of() { wc -c < "$1" | tr -d ' '; }

verify_entry() { # $1 = 文件
  [ -f "$1" ] || return 1
  actual_size=$(size_of "$1")
  [ "$actual_size" = "$SIZE" ] || { echo "size 不匹配：$actual_size != $SIZE" >&2; return 1; }
  actual_sha=$(sha_of "$1")
  [ "$actual_sha" = "$SHA" ] || { echo "sha256 不匹配：$actual_sha != $SHA" >&2; return 1; }
  return 0
}

if verify_entry "$DEST"; then
  echo "ksud 已就绪：$DEST ($TAG, sha256=$SHA)"
  exit 0
fi

mkdir -p "$CACHE"
APK="$CACHE/KernelSU-$TAG.apk"
if [ ! -f "$APK" ] || [ "$(sha_of "$APK")" != "$APK_SHA" ]; then
  echo "下载 $URL"
  TMP="$APK.part"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$TMP" "$URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$TMP" "$URL"
  else
    echo "没有 curl/wget" >&2; exit 1
  fi
  actual_apk=$(sha_of "$TMP")
  if [ "$actual_apk" != "$APK_SHA" ]; then
    rm -f "$TMP"
    echo "APK 哈希不符：$actual_apk != $APK_SHA" >&2
    exit 1
  fi
  mv -f "$TMP" "$APK"
fi

command -v unzip >/dev/null 2>&1 || { echo "没有 unzip，无法从 APK 取 $ENTRY" >&2; exit 1; }
STAGE="$CACHE/ksud-$TAG"
unzip -p "$APK" "$ENTRY" > "$STAGE.part"
if ! verify_entry "$STAGE.part"; then
  rm -f "$STAGE.part"
  echo "从 APK 取出的 $ENTRY 校验失败" >&2
  exit 1
fi
mv -f "$STAGE.part" "$STAGE"

mkdir -p "$(dirname "$DEST")"
cp -f "$STAGE" "$DEST.new"
chmod 755 "$DEST.new" 2>/dev/null || true
mv -f "$DEST.new" "$DEST"
verify_entry "$DEST"
echo "ksud 已安装：$DEST ($TAG, sha256=$SHA)"
