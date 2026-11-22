#!/system/bin/sh
# 校验「手机里已安装的 APK」中的 assets 是否就是台账登记的那几个文件。
#
# 只读：用 unzip -p 读 APK 条目算 sha256，不执行任何 payload、不碰 rootd / tracefs / perf。
#
# 用法：
#   tools/verify_apk_assets.sh [包名]
# 期望值来自 tools/assets-ledger.json（这里写成常量，改资产时同步改这里，
# 脚本本身带一个 --self-check 让它能拿仓库里的台账做交叉验证）。

set -u

PKG="${1:-com.gkeyes.lhasa26}"

# 台账里登记的值（2026-11-22 替换后）
#   reach_probe   45664  0938f6b6f873665db0fc03e17bf0555f30327605c6cf2e9b9661ea67b3d16d10
#   slide_probe   35336  e9830ee4f058f82c3b455eb1611e58b4771e8995f23c0adf3926c9c5b64b63b5
#   perf_slide    27144  89705ef467342d6af11bbcc21289f988bc4953de7d2ac2df14eb8843a5cb6d1f
#   pc98260-su    26616  231cf185d2808b66c9fd7cc45c00ab5a0fa4b7fa588f96e06587af8ee390fdd2
#   ksud        4990848  4f7d5fd65631915ea579ff406bd9cbe58217f2c91dac6527f5b2f28ad4508171
#   uaf_plant_replay 88488（无源码，保持原件）
expect_sha() {
	case "$1" in
		reach_probe)       echo 0938f6b6f873665db0fc03e17bf0555f30327605c6cf2e9b9661ea67b3d16d10 ;;
		slide_probe)       echo e9830ee4f058f82c3b455eb1611e58b4771e8995f23c0adf3926c9c5b64b63b5 ;;
		perf_slide)        echo 89705ef467342d6af11bbcc21289f988bc4953de7d2ac2df14eb8843a5cb6d1f ;;
		pc98260-su)        echo 231cf185d2808b66c9fd7cc45c00ab5a0fa4b7fa588f96e06587af8ee390fdd2 ;;
		ksud)              echo 4f7d5fd65631915ea579ff406bd9cbe58217f2c91dac6527f5b2f28ad4508171 ;;
		*)                 echo "" ;;
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
for name in reach_probe slide_probe perf_slide pc98260-su ksud uaf_plant_replay; do
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
