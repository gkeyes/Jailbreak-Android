/*
 * reach_probe — 接口可达性诊断。
 *
 * 按原件字符串表重建（CI Artifact 的 strings/reach_probe.orig.txt）。
 * 原件同时存在「裸路径」和「带尾随空格的列名」两套字面量，例如
 *   /proc/kallsyms            ← open 用
 *   /proc/kallsyms            + 空格  ← 表格里名字列用
 *   /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw
 *   per_cpu/cpu0/trace_pipe_raw + 空格
 * 表格格式： "  [%s] %-40s %s"，汇总：" OK " / " FAIL " / " %d " / " ---"。
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
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <linux/aio_abi.h>
#include <linux/perf_event.h>

static int g_ok, g_fail;

/* 裸路径（open 用） */
static const char *P_KALLSYMS = "/proc/kallsyms";
static const char *P_SLABINFO = "/proc/slabinfo";
static const char *P_TRACEFS  = "/sys/kernel/tracing";
static const char *P_PIPE     = "/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw";
static const char *P_KMEM_EN  = "/sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable";
static const char *P_RSS_TRIG = "/sys/kernel/tracing/events/kmem/rss_stat/trigger";
static const char *P_KPROBE   = "/sys/kernel/tracing/kprobe_events";
static const char *P_TRACE_ON = "/sys/kernel/tracing/tracing_on";

/* 列名（带尾随空格，和原件一致） */
static const char *N_KALLSYMS = "/proc/kallsyms ";
static const char *N_SLABINFO = "/proc/slabinfo ";
static const char *N_TRACEFS  = "/sys/kernel/tracing ";
static const char *N_PIPE     = "/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw ";
static const char *N_PIPE_SHORT = "per_cpu/cpu0/trace_pipe_raw ";
static const char *N_KMEM_EN  = "kmem_cache_alloc/enable ";
static const char *N_RSS_TRIG = "kmem/rss_stat/trigger ";
static const char *N_KPROBE   = "kprobe_events ";
static const char *N_TRACE_ON = "tracing_on ";

static void report(const char *name, int ok, const char *detail)
{
	if (ok)
		g_ok++;
	else
		g_fail++;
	printf("  [%s] %-40s %s\n", ok ? "OK" : "FAIL", name, detail && *detail ? detail : "");
}

static int can_open(const char *path, int flags, char *detail, size_t len)
{
	int fd = open(path, flags | O_CLOEXEC);
	if (fd < 0) {
		snprintf(detail, len, "errno=%d (%s)", errno, strerror(errno));
		return 0;
	}
	close(fd);
	snprintf(detail, len, "open ok");
	return 1;
}

static int has_line(const char *path, const char *needle, char *detail, size_t len)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		snprintf(detail, len, "errno=%d (%s)", errno, strerror(errno));
		return 0;
	}
	char buffer[4096];
	ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (n <= 0) {
		snprintf(detail, len, "n=%zd", n);
		return 0;
	}
	buffer[n] = '\0';
	snprintf(detail, len, "present=1");
	return strstr(buffer, needle) != NULL;
}

static void capture(const char *command, char *out, size_t len, char *detail, size_t dlen)
{
	out[0] = '\0';
	FILE *pipe = popen(command, "r");
	if (!pipe) {
		snprintf(detail, dlen, "popen errno=%d", errno);
		return;
	}
	size_t used = 0;
	if (fgets(out, (int)len, pipe) != NULL)
		used = strlen(out);
	while (used > 0 && (out[used - 1] == '\n' || out[used - 1] == ' '))
		out[--used] = '\0';
	pclose(pipe);
	snprintf(detail, dlen, "%s", used ? out : "empty");
}

static int perf_event_open_software(void)
{
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_SOFTWARE;
	attr.size = PERF_ATTR_SIZE_VER5;
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.disabled = 1;
	return (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
}

static int unix_stream_8k(void)
{
	int fd[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) != 0)
		return -1;
	char chunk[8192];
	memset(chunk, 'A', sizeof(chunk));
	ssize_t n = write(fd[0], chunk, sizeof(chunk));
	close(fd[0]);
	close(fd[1]);
	return n == (ssize_t)sizeof(chunk) ? 0 : -1;
}

/* 直接走 syscall：musl 静态下不依赖 libc 的 AIO 包装。 */
static int aio_setup_probe(void)
{
	aio_context_t ctx = 0;
	long ret = syscall(SYS_io_setup, 1, &ctx);
	if (ret == 0 && ctx != 0) {
		syscall(SYS_io_destroy, ctx);
		return 0;
	}
	return -1;
}

static int thread_timer(void)
{
	timer_t timer;
	struct sigevent sev;
	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGUSR1;
	if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &timer) != 0)
		return -1;
	timer_delete(timer);
	return 0;
}

int main(void)
{
	char detail[256];
	char value[256];

	printf("<=== CVE-2026-98260 / lhasa ===\n");

	capture("id", value, sizeof(value), detail, sizeof(detail));
	printf("  id              : %s\n", value);

	capture("uname -r", value, sizeof(value), detail, sizeof(detail));
	printf("  kernel version  : %s\n", value);
	printf("  uname -r        : %s\n", value);

	capture("getprop ro.product.device", value, sizeof(value), detail, sizeof(detail));
	printf("  ro.product.device: %s\n", value);

	capture("getprop ro.product.model", value, sizeof(value), detail, sizeof(detail));
	printf("  ro.product.model : %s\n", value);

	capture("getenforce", value, sizeof(value), detail, sizeof(detail));
	printf("  getenforce      : %s\n", value);

	capture("grep -m1 posix_timers_cache /proc/slabinfo",
		value, sizeof(value), detail, sizeof(detail));
	printf("  posix_timers_cache:\n         : %s\n", value);

	printf("--- tracefs\n");
	report(N_KALLSYMS, can_open(P_KALLSYMS, O_RDONLY, detail, sizeof(detail)), detail);
	report(N_SLABINFO, has_line(P_SLABINFO, "kmem_cache_alloc", detail, sizeof(detail)), detail);
	report("/proc/self/pagemap", can_open("/proc/self/pagemap", O_RDONLY, detail, sizeof(detail)), detail);
	report(N_TRACEFS, can_open(P_TRACEFS, O_RDONLY, detail, sizeof(detail)), detail);
	report(N_TRACE_ON, can_open(P_TRACE_ON, O_RDONLY, detail, sizeof(detail)), detail);
	report(N_KMEM_EN, can_open(P_KMEM_EN, O_WRONLY, detail, sizeof(detail)), detail);
	report(N_RSS_TRIG, can_open(P_RSS_TRIG, O_WRONLY, detail, sizeof(detail)), detail);
	report(N_KPROBE, can_open(P_KPROBE, O_WRONLY, detail, sizeof(detail)), detail);

	int pipe_ok = can_open(P_PIPE, O_RDONLY | O_NONBLOCK, detail, sizeof(detail));
	report(N_PIPE, pipe_ok, pipe_ok ? "trace_pipe_raw 可打开" : detail);
	if (pipe_ok)
		printf("  --- %s OK \n", N_PIPE_SHORT);

	report("/dev/null", can_open("/dev/null", O_WRONLY, detail, sizeof(detail)), detail);
	report("/bin/sh", access("/bin/sh", X_OK) == 0 ? 1 : 0, "access ok");

	printf("--- \n");
	int perf_fd = perf_event_open_software();
	if (perf_fd < 0) {
		snprintf(detail, sizeof(detail), "errno=%d (%s)", errno, strerror(errno));
		report("perf_event_open (software)", 0, detail);
	} else {
		close(perf_fd);
		report("perf_event_open (software)", 1, "ok");
	}

	if (unix_stream_8k() != 0) {
		snprintf(detail, sizeof(detail), "socketpair errno=%d", errno);
		report("unix SOCK_STREAM 8KB write", 0, detail);
	} else {
		report("unix SOCK_STREAM 8KB write", 1, "write ok");
	}

	if (aio_setup_probe() != 0) {
		snprintf(detail, sizeof(detail), "errno=%d (%s)", errno, strerror(errno));
		report("io_setup (AIO)", 0, detail);
	} else {
		report("io_setup (AIO)", 1, "ok");
	}

	if (thread_timer() != 0) {
		snprintf(detail, sizeof(detail), "timer_create errno=%d", errno);
		report("timer_create(CLOCK_THREAD_CPUTIME)", 0, detail);
	} else {
		report("timer_create(CLOCK_THREAD_CPUTIME)", 1, "ok");
	}

	/* 汇总行沿用原件的三段字面量：" %d "、" OK "、" FAIL "。 */
	printf("\n %d %s\n", g_ok, " OK ");
	printf(" %d %s\n", g_fail, " FAIL ");
	printf("  %d ok / %d fail\n", g_ok, g_fail);

	if (g_fail == 0) {
		printf("必需项全部通过\n");
		return 0;
	}
	printf("必需接口不可用\n");
	return 1;
}
