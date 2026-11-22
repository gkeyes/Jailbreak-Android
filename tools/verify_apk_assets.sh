#!/system/bin/sh
# 校验「手机里已安装的 APK」中的 assets 是否就是台账登记的那几个文件。
#
# 只读：用 unzip -p 读 APK 条目算 sha256，不执行任何 payload、不碰 rootd / tracefs / perf。
#
# 用法：tools/verify_apk_assets.sh [包名]
#
# 期望值必须与 tools/assets-ledger.json 保持一致；改动 assets 后要同步这里。
# 装完包先跑这个，确认 APK 里装的确实是我们编的二进制，再去判断提权结果——
# 否则「提权失败」可能只是包没换对。

set -u

PKG="${1:-com.gkeyes.lhasa26}"

# 台账现值（0.4.0-dev，2026-11-22）
#   perf_slide    37376  be977d32…  软件事件回退 + --duration 按秒 + profile 投票
#   slide_probe   35352  8b3681cb…  先开 trace 再 timer_create
#   reach_probe   45664  0938f6b6…
#   pc98260-su    26616  231cf185…
#   ksud        4990848  4f7d5fd6…  上游原件（KernelSU v3.3.1 的 libksud.so）
#   uaf_plant_replay 88488（无源码，保持原件）
expect_sha() {
	case "$1" in
		perf_slide)  echo be977d32d3def2fe6673403f4fd92626af8fe68eb1439f7d5fca49f723d89aca ;;
		slide_probe) echo 8b3681cbd2966eefe5a800b8964e58253ff338b37bffe997b4d891933c8c9e3c ;;
		reach_probe) echo 0938f6b6f873665db0fc03e17bf0555f30327605c6cf2e9b9661ea67b3d16d10 ;;
		pc98260-su)  echo 231cf185d2808b66c9fd7cc45c00ab5a0fa4b7fa588f96e06587af8ee390fdd2 ;;
		ksud)        echo 4f7d5fd65631915ea579ff406bd9cbe58217f2c91dac6527f5b2f28ad4508171 ;;
		*)           echo "" ;;
	esac
}

apk_path=$(pm path "$PKG" 2>/dev/null | head -1 | sed 's/^package://')
if [ -z "$apk_path" ]; then
	echo "找不到包 $PKG（没装？）"
	exit 2
fi
echo "APK: $apk_path"

work="${TMPDIR:-/data/local/tmp}/apk-assets-check.$$"
mkdir -p "$work" || exit 1
trap 'rm -rf "$work"' EXIT

fail=0
for name in perf_slide slide_probe reach_probe pc98260-su ksud uaf_plant_replay; do
	if ! unzip -p "$apk_path" "assets/$name" > "$work/$name" 2>/dev/null || [ ! -s "$work/$name" ]; then
		echo "缺失 assets/$name"
		fail=1
		continue
	fi
	actual=$(sha256sum "$work/$name" | cut -d' ' -f1)
	size=$(wc -c < "$work/$name" | tr -d ' ')
	want=$(expect_sha "$name")

	if [ -z "$want" ]; then
		echo "OK?  assets/$name  $size 字节（台账未固定 sha256，只报大小）"
		continue
	fi
	if [ "$actual" = "$want" ]; then
		echo "OK   assets/$name  $size 字节  sha256=${actual}"
	else
		echo "FAIL assets/$name  $size 字节"
		echo "     期望 $want"
		echo "     实际 $actual"
		fail=1
	fi
done

echo
if [ "$fail" -eq 0 ]; then
	echo "APK 内的 assets 与台账一致"
else
	echo "APK 内的 assets 与台账不一致"
fi
exit "$fail"
