#!/system/bin/sh
# 闸 2（pc98260-su）：只比「连接失败」与「参数解析」，不碰 rootd、不碰内核。
#
# 背景：rootd 是 uaf_plant_replay 在已经被 UAF 污染的堆上起的临时通道。
# 去连它发命令 = 复用不稳定的内核状态，实测会让设备 panic 重启（2026-11-22）。
#
# 现在 pc98260-su 由上游 MIT 源码构建（tools/build_xring.sh），这条闸的意义
# 变成「协议是否与原件一致」：长度前缀那段就是在这种比对里发现漏掉的。
#
#   用例 1  PC98260_SOCK 指向不存在的 socket + -c id
#   用例 2  不带参数 → usage
#   用例 3  -h        → usage
#
# 用法：gate2_pc98260.sh [原件路径] [新件路径]
#   默认 原件 /data/local/tmp/plant/orig/pc98260-su
#        新件 /data/local/tmp/pc98260-su（App 部署的那份）

set -u

ORIG="${1:-/data/local/tmp/plant/orig/pc98260-su}"
NEW="${2:-/data/local/tmp/pc98260-su}"
WORK="${WORK:-/data/local/tmp/gate2}"
OUT="$WORK/logs"

mkdir -p "$OUT" || exit 1

for bin in "$ORIG" "$NEW"; do
	[ -x "$bin" ] || { echo "缺少可执行文件：$bin"; exit 2; }
done

normalize() {
	sed -E \
		-e 's/pid=[0-9]+/pid=PID/g' \
		-e 's/0x[0-9a-fA-F]+/0xADDR/g'
}

run_case() {
	label="$1"
	orig_bin="$2"
	new_bin="$3"
	shift 3

	env_sock="$WORK/nonexistent-$$.sock"
	rm -f "$env_sock"

	(
		cd "$WORK" || exit 1
		PC98260_SOCK="$env_sock" "$orig_bin" "$@" > "$OUT/$label.orig.stdout" 2> "$OUT/$label.orig.stderr"
		echo $? > "$OUT/$label.orig.code"
		PC98260_SOCK="$env_sock" "$new_bin" "$@" > "$OUT/$label.new.stdout" 2> "$OUT/$label.new.stderr"
		echo $? > "$OUT/$label.new.code"
	)

	normalize < "$OUT/$label.orig.stdout" > "$OUT/$label.orig.norm"
	normalize < "$OUT/$label.new.stdout" > "$OUT/$label.new.norm"
	normalize < "$OUT/$label.orig.stderr" > "$OUT/$label.orig.err.norm"
	normalize < "$OUT/$label.new.stderr" > "$OUT/$label.new.err.norm"

	oc=$(cat "$OUT/$label.orig.code")
	nc=$(cat "$OUT/$label.new.code")

	status=PASS
	if [ "$oc" != "$nc" ]; then
		status=DIFF
		echo "[$label] 退出码不同：orig=$oc new=$nc"
	fi
	if ! diff -u "$OUT/$label.orig.norm" "$OUT/$label.new.norm" > "$OUT/$label.stdout.diff"; then
		status=DIFF
		echo "[$label] stdout 不同，见 $OUT/$label.stdout.diff"
	else
		rm -f "$OUT/$label.stdout.diff"
	fi
	if ! diff -u "$OUT/$label.orig.err.norm" "$OUT/$label.new.err.norm" > "$OUT/$label.stderr.diff"; then
		status=DIFF
		echo "[$label] stderr 不同，见 $OUT/$label.stderr.diff"
	else
		rm -f "$OUT/$label.stderr.diff"
	fi

	echo "[$label] $status"
	[ "$status" = PASS ]
}

fail=0

run_case connect-fail "$ORIG" "$NEW" -c 'id' || fail=1
run_case usage-noargs "$ORIG" "$NEW" || fail=1
run_case usage-help "$ORIG" "$NEW" -h || fail=1

echo
echo "日志目录：$OUT"
if [ "$fail" -eq 0 ]; then
	echo "闸 2（pc98260-su 协议）全部通过"
else
	echo "闸 2 有差异，先看 .diff"
fi
exit "$fail"
