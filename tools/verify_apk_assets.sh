#!/system/bin/sh
# 校验「手机里已安装的 APK」里的 assets 是否与台账一致。
#
# 只读：用 unzip -p 读 APK 条目算 sha256，不执行任何 payload、不碰 rootd / tracefs / perf。
#
# 期望值来自 tools/assets-ledger.json（唯一事实来源）。解析不看字段顺序：
# 逐个资产对象收集 name 与 sha256，遇到下一个 name 才收尾。
# **摘要缺失一律判失败**——旧版把空摘要当成"未固定"放过，会把错误文件判成通过。
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

# 按对象收集 name→sha256，不受字段顺序影响。
expected() {
	awk -v want="$1" '
		/"name":/ {
			if (nm == want) { print sha; done = 1; exit }
			nm = $0; sub(/.*"name": *"/, "", nm); sub(/".*/, "", nm)
			sha = ""
		}
		/"sha256":/ {
			s = $0
			sub(/.*"sha256": *"/, "", s); sub(/".*/, "", s)
			if (s != "" && s != "null") sha = s
		}
		END { if (!done && nm == want) print sha }
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
	want=$(expected "$name")

	if [ -z "$want" ]; then
		echo "FAIL assets/$name —— 台账里没有该资产的 sha256（解析失败或未登记）"
		fail=1
		continue
	fi

	if ! unzip -p "$apk_path" "assets/$name" > "$work/$name" 2>/dev/null || [ ! -s "$work/$name" ]; then
		echo "FAIL assets/$name —— APK 中缺失或为空"
		fail=1
		continue
	fi

	actual=$(sha256sum "$work/$name" | cut -d' ' -f1)
	size=$(wc -c < "$work/$name" | tr -d ' ')

	if [ "$actual" = "$want" ]; then
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
	echo "APK 内的 assets 与台账一致（6/6）"
else
	echo "APK 内的 assets 与台账不一致"
fi
exit "$fail"
