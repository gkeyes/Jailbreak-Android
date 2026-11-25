#!/system/bin/sh
# S0/S1 只读预检：环境基线 + 99491 可达性。不写内核、不改参数。
# 输出固定写到 /sdcard/Download/DSH-Go/99491/<boot_id>/s1_precheck.txt
set -u
DIR=/sdcard/Download/DSH-Go/99491
BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
RUN="$DIR/$BOOT"
mkdir -p "$RUN" 2>/dev/null
F="$RUN/s1_precheck.txt"
{
  echo "## date=$(date 2>/dev/null)"
  echo "## uname=$(uname -r)"
  echo "## build=$(uname -v)"
  echo "## boot_id=$BOOT"
  echo "## enforce=$(getenforce)"
  echo "## spl=$(getprop ro.build.version.security_patch)"
  echo "## incremental=$(getprop ro.build.version.incremental)"
  echo "## fingerprint=$(getprop ro.build.fingerprint)"
  echo "## identity=$(id 2>&1)"
  echo
  echo "## /dev/uhid=$(ls -l /dev/uhid 2>&1)"
  echo "## /dev/uinput=$(ls -l /dev/uinput 2>&1)"
  echo "## hidraw=$(ls /dev/hidraw* 2>&1 | tr '\n' ' ')"
  echo "## wacom_driver=$(ls -d /sys/bus/hid/drivers/wacom 2>&1)"
  echo "## wacom_module=$(ls -d /sys/module/wacom 2>&1)"
  echo "## input_nodes=$(ls /dev/input 2>&1 | tr '\n' ' ')"
  echo "## tracefs_trigger=$(ls -l /sys/kernel/tracing/events/kmem/rss_stat/trigger 2>&1)"
  echo "## tracefs_raw=$(ls -l /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw 2>&1)"
  echo "## tracing_on=$(cat /sys/kernel/tracing/tracing_on 2>&1)"
  echo "## kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>&1)"
  echo "## slide_cache=$(cat /data/local/tmp/.lhasa_slide 2>&1)"
  echo "## online_cpus=$(cat /sys/devices/system/cpu/online 2>&1)"
  echo "## page_size=$(getconf PAGESIZE 2>/dev/null || echo unknown)"
  echo "## su=$(ls -l /system/bin/su 2>&1)"
  echo "## kernelsu_pkg=$(pm list packages 2>/dev/null | grep -i kernelsu | tr '\n' ' ')"
  echo "## kernelsu_path=$(pm path me.weishu.kernelsu 2>&1)"
  echo "## tmp_dir=$(ls /data/local/tmp 2>&1 | tr '\n' ' ')"
  echo
  echo "## modules_begin"
  head -60 /proc/modules 2>&1
  echo "## modules_end"
} > "$F" 2>&1
chmod 644 "$F" 2>/dev/null
cat "$F"
echo "S1_PRECHECK_DONE file=$F"
