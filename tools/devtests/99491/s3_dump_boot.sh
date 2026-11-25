#!/system/bin/sh
# S3 只读导出（需要在已授权的 KernelSU root 会话里执行本脚本）。
# 导出：/proc/kallsyms（临时 kptr_restrict=0，立即恢复）、/sys/kernel/btf/vmlinux、当前槽位 boot 分区。
# 全部写入 /data/local/tmp/99491dump/，不改分区、不写设备其他位置。
set -u
OUT=/data/local/tmp/99491dump
mkdir -p "$OUT" 2>/dev/null
ORIG=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
[ -n "${ORIG:-}" ] || ORIG=2

restore() {
  echo "$ORIG" > /proc/sys/kernel/kptr_restrict 2>/dev/null
}
trap restore EXIT HUP INT TERM

echo "## kptr_restrict orig=$ORIG"
echo 0 > /proc/sys/kernel/kptr_restrict 2>&1
cat /proc/kallsyms > "$OUT/kallsyms.txt" 2>&1
echo "## kallsyms bytes=$(wc -c < "$OUT/kallsyms.txt" 2>/dev/null)"
cat /sys/kernel/btf/vmlinux > "$OUT/vmlinux.btf" 2>&1
echo "## btf bytes=$(wc -c < "$OUT/vmlinux.btf" 2>/dev/null)"

SLOT=$(getprop ro.boot.slot_suffix 2>/dev/null)
[ -n "${SLOT:-}" ] || SLOT=_a
BYNAME="/dev/block/by-name/boot$SLOT"
[ -e "$BYNAME" ] || BYNAME="/dev/block/bootdevice/by-name/boot$SLOT"
echo "## boot_slot=$SLOT byname=$BYNAME"
if [ -r "$BYNAME" ]; then
  dd if="$BYNAME" of="$OUT/boot.img" bs=1048576 2>&1 | tail -2
  echo "## boot.img bytes=$(wc -c < "$OUT/boot.img" 2>/dev/null)"
else
  echo "## boot part not readable: $BYNAME"
fi

restore
trap - EXIT HUP INT TERM
echo "## kptr_restrict restored=$(cat /proc/sys/kernel/kptr_restrict 2>&1)"
chmod 644 "$OUT"/* 2>/dev/null
ls -l "$OUT"
echo "S3_DUMP_DONE dir=$OUT"
