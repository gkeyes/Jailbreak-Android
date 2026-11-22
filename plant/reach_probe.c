/*
 * reach_probe — 接口可达性诊断。
 *
 * 输出固定包含 "必需项全部通过" 或 "必需接口不可用"，Java 侧 runDiagnosis() 依赖这两个字符串。
 *
 * 与原件的一个差异：perf_event_open 的 attr.size 固定为 PERF_ATTR_SIZE_VER5(112)。
 * 原件用较新的工具链编译，attr.size 超出 6.18 内核接受的尺寸，会拿到 E2BIG，导致诊断日志里
 * 出现一条假的 perf_event_open FAIL（WorkflowEngine 里有一段专门绕开它的逻辑）。
 * 自己编译后这个误报不应该再出现。
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#define ATTR_SIZE PERF_ATTR_SIZE_VER5
#define TRACE_PIPE "/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw"
#define MAX_MAP_COUNT_MIN 60000L

static int g_failures;

static void report(const char *name, int ok, const char *detail)
{
	if (!ok)
		g_failures++;
	printf("[probe] %-30s %s%s%s\n", name, ok ? "OK" : "FAIL",
	       (detail && *detail) ? "  " : "", (detail && *detail) ? detail : "");
}

static int perf_open(uint32_t type, uint64_t config)
{
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.type = type;
	attr.size = ATTR_SIZE;
	attr.config = config;
	attr.disabled = 1;
	return (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
}

static int perf_event_open_software(void)
{
	int fd = perf_open(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

static int perf_event_open_hardware(void)
{
	int fd = perf_open(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

static long read_long(const char *path)
{
	char buffer[64];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buffer[n] = '\0';
	return strtol(buffer, NULL, 10);
}

static int check_tracefs(char *detail, size_t len)
{
	int fd = open(TRACE_PIPE, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		snprintf(detail, len, "%s: %s", TRACE_PIPE, strerror(errno));
		return 0;
	}
	close(fd);
	snprintf(detail, len, "%s 可打开", TRACE_PIPE);
	return 1;
}

static int check_timer(char *detail, size_t len)
{
	timer_t timer;
	struct sigevent sev;
	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGUSR1;
	if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &timer) != 0) {
		snprintf(detail, len, "timer_create: %s", strerror(errno));
		return 0;
	}
	timer_delete(timer);
	snprintf(detail, len, "CLOCK_THREAD_CPUTIME_ID + SIGEV_SIGNAL");
	return 1;
}

int main(void)
{
	char detail[160];

	detail[0] = '\0';
	report("tracefs (trace_pipe_raw)", check_tracefs(detail, sizeof(detail)), detail);

	int software = perf_event_open_software();
	if (software < 0)
		snprintf(detail, sizeof(detail), "errno=%d (%s)", errno, strerror(errno));
	else
		snprintf(detail, sizeof(detail), "PERF_COUNT_SW_CPU_CLOCK");
	report("perf_event_open (software)", software == 0, detail);

	int hardware = perf_event_open_hardware();
	if (hardware < 0)
		snprintf(detail, sizeof(detail), "errno=%d (%s)", errno, strerror(errno));
	else
		snprintf(detail, sizeof(detail), "PERF_COUNT_HW_CPU_CYCLES");
	report("perf_event_open (hardware)", hardware == 0, detail);

	report("timer_create (thread cpu)", check_timer(detail, sizeof(detail)), detail);

	long max_map = read_long("/proc/sys/vm/max_map_count");
	snprintf(detail, sizeof(detail), "max_map_count=%ld（门槛 %ld）", max_map, MAX_MAP_COUNT_MIN);
	report("vm.max_map_count", max_map >= MAX_MAP_COUNT_MIN, detail);

	long paranoid = read_long("/proc/sys/kernel/perf_event_paranoid");
	snprintf(detail, sizeof(detail), "perf_event_paranoid=%ld", paranoid);
	report("perf_event_paranoid", paranoid <= 1, detail);

	char enforce[16];
	memset(enforce, 0, sizeof(enforce));
	int selinux_ok = 0;
	int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t n = read(fd, enforce, sizeof(enforce) - 1);
		close(fd);
		selinux_ok = n > 0;
	}
	snprintf(detail, sizeof(detail), "enforce=%s", selinux_ok ? enforce : "?");
	report("/sys/fs/selinux/enforce", selinux_ok, detail);

	printf("\n");
	if (g_failures == 0) {
		printf("必需项全部通过\n");
		return 0;
	}
	printf("必需接口不可用：%d 项失败\n", g_failures);
	printf("提示：上面标记 FAIL 的行就是缺失的能力，先解决它们再跑主利用。\n");
	return 1;
}
