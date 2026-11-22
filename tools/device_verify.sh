#!/system/bin/sh
# 闸 2：在设备上跑「原件 vs 重建物」成对执行并比对输出。
#
# 需要 root（或 Shizuku 提权后的 shell）——perf/tracefs 这些接口普通权限拿不到。
#
# 用法（在设备上，root shell 里）：
#   device_verify.sh run [原件目录] [重建目录] [工作目录]
#   默认：/data/local/tmp/plant/orig  /data/local/tmp/plant/new  /data/local/tmp/plant/out
#
# 每个资产按下面的固定参数各跑一次，输出存到 $OUT/<名字>.<orig|new>.log：
#   pc98260-su        -c 'id'
#   reach_probe       （无参数）
#   slide_probe       （无参数）
#   perf_slide        --period 1000 --duration 300
#   uaf_plant_replay  不参与（无源码，见台账）
#
# 比对规则：
#   - 退出码必须一致
#   - 归一化后逐行 diff（pid / 字节数 / 耗时 / 地址都归一）
#   - 锚点行（OK/FAIL 行、[slide]/[perf]/[stream] 前缀行）不许增加或消失
#
# 参数与归一化规则就写在这里，别在提交信息里散着写。
set -u

CMD="${1:-}"
[ "$CMD" = "run" ] || { sed -n '2,20p' "$0"; exit 2; }
shift

ORIG_DIR="${1:-/data/local/tmp/plant/orig}"
NEW_DIR="${2:-/data/local/tmp/plant/new}"
WORK="${3:-/data/local/tmp/plant/out}"
OUT="$WORK/logs"

mkdir -p "$OUT" || exit 1

normalize() {
	sed -E \
		-e 's/pid=[0-9]+/pid=PID/g' \
		-e 's/bytes=[0-9]+/bytes=N/g' \
		-e 's/elapsed=[0-9]+s/elapsed=Ts/g' \
		-e 's/[0-9]+ s$/[T] s/' \
		-e 's/(tid|tgid|req|captured)=[0-9]+/\1=N/g' \
		-e 's/0x[0-9a-fA-F]+/0xADDR/g'
}

run_one() {
	name="$1"
	bin="$2"
	log="$3"
	shift 3

	[ -x "$bin" ] || { echo "missing $bin"; return 2; }
	(cd "$WORK" && "$bin" "$@") > "$log.stdout" 2> "$log.stderr"
	echo $? > "$log.code"
	normalize < "$log.stdout" > "$log"
}

compare_one() {
	name="$1"
	a="$OUT/$name.orig.log"
	b="$OUT/$name.new.log"
	ca=$(cat "$OUT/$name.orig.code")
	cb=$(cat "$OUT/$name.new.code")

	status=PASS
	if [ "$ca" != "$cb" ]; then
		status=DIFF
		echo "[$name] 退出码不同：orig=$ca new=$cb"
	fi
	if ! diff -u "$a" "$b" > "$OUT/$name.diff"; then
		status=DIFF
		echo "[$name] 输出不同，见 $OUT/$name.diff"
	else
		rm -f "$OUT/$name.diff"
	fi
	echo "[$name] $status"
	[ "$status" = PASS ]
}

fail=0

run_one pc98260-su "$ORIG_DIR/pc98260-su" "$OUT/pc98260-su.orig" -c 'id'
run_one pc98260-su "$NEW_DIR/pc98260-su" "$OUT/pc98260-su.new" -c 'id'
compare_one pc98260-su || fail=1

run_one reach_probe "$ORIG_DIR/reach_probe" "$OUT/reach_probe.orig"
run_one reach_probe "$NEW_DIR/reach_probe" "$OUT/reach_probe.new"
compare_one reach_probe || fail=1

run_one slide_probe "$ORIG_DIR/slide_probe" "$OUT/slide_probe.orig"
run_one slide_probe "$NEW_DIR/slide_probe" "$OUT/slide_probe.new"
compare_one slide_probe || fail=1

run_one perf_slide "$ORIG_DIR/perf_slide" "$OUT/perf_slide.orig" --period 1000 --duration 300
run_one perf_slide "$NEW_DIR/perf_slide" "$OUT/perf_slide.new" --period 1000 --duration 300
compare_one perf_slide || fail=1

echo
echo "日志目录：$OUT"
if [ "$fail" -eq 0 ]; then
	echo "闸 2 全部通过"
else
	echo "闸 2 有差异，先看 .diff 再决定是否替换"
fi
exit "$fail"
