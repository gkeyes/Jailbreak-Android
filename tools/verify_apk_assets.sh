#!/system/bin/sh
# 校验「手机里已安装的 APK」里的 assets 是否与台账一致。
#
# 只读：用 unzip -p 读 APK 条目算 sha256，不执行任何 payload、不碰 rootd / tracefs / perf。
#
# 期望值直接取自 tools/assets-ledger.json（唯一事实来源），不再硬编码。
#
# 注意：`lhasa_profile.txt` 现在是**构建期输入**（tools/gen_xr_profiles.py 读它生成
# 编译期 profile 表），App 运行时不再把它推到设备上；但它仍打进 APK，所以这里照样校验。
#
# 用法：tools/verify_apk_assets.sh [包名] [台账路径]

set -u

PKG="${1:-com.gkeyes.lhasa26}"
LEDGER="${2:-/data/local/tmp/assets-ledger.json}"

if [ ! -f "$LEDGER" ]; then
	LEDGER="$(dirname "$0")/../tools/assets-ledger.json"
fi
if [ ! -f "$LEDGER" ]; then
	echo "找不到台账：$LEDGER"
	echo "用法：$0 [包名] [台账路径]"
	exit 2
fi

expected() {
	awk -v want="$1" '
		/"name": *"/ {
			line = $0
			sub(/.*"name": *"/, "", line)
			sub(/".*/, "", line)
			name = line
			sha = ""
		}
		/"sha256": *"/ {
			line = $0
			sub(/.*"sha256": *"/, "", line)
			sub(/".*/, "", line)
			sha = line
		}
		/"sha256": *null/ { sha = "" }
		/"gitBlobSha1"/ {
			if (name == want) { print sha; exit }
		}
	' "$LEDGER"
}

apk_path=$(pm path "$PKG" 2>/dev/null | head -1 | sed 's/^package://')
if [ -z "$apk_path" ]; then
	echo "找不到包 $PKG（没装？）"
	exit 2
fi
echo "APK: $apk_path"
echo "台账: $LEDGER"

work="${TMPDIR:-/data/local/tmp}/apk-assets-check.$$"
mkdir -p "$work" || exit 1
trap 'rm -rf "$work"' EXIT

fail=0
for name in reach_probe slide_probe pc98260-su uaf_plant_replay ksud lhasa_profile.txt; do
	if ! unzip -p "$apk_path" "assets/$name" > "$work/$name" 2>/dev/null || [ ! -s "$work/$name" ]; then
		echo "缺失 assets/$name"
		fail=1
		continue
	fi
	actual=$(sha256sum "$work/$name" | cut -d' ' -f1)
	size=$(wc -c < "$work/$name" | tr -d ' ')
	want=$(expected "$name")

	if [ -z "$want" ]; then
		echo "OK?  assets/$name  $size 字节（台账未固定 sha256）"
	elif [ "$actual" = "$want" ]; then
		echo "OK   assets/$name  $size 字节"
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
