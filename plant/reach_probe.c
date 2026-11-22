/*
 * reach_probe — 接口可达性诊断。
 *
 * 按真机实测输出逐行对齐（2026-11-22，6.18.21-android17 上跑原件得到）：
 *
 *   === CVE-2026-98260 / lhasa 环境诊断（重写版）===
 *     uname -r        : ...
 *     kernel version  : #1 SMP PREEMPT ...
 *     ro.product.device: lhasa
 *     ro.product.model : 2608BPX34C
 *     系统增量         : OS4.0.21.0.XPNCNXM
 *     getenforce      : Enforcing
 *     id              : uid=0(root) ...
 *
 *   --- 内核信息泄露面 ---
 *     [ OK ] /proc/slabinfo 可读                    open ok
 *   --- tracefs（决定整条链能否观测）---
 *   --- 系统调用面 ---
 *   --- 结论 ---
 *     12 ok / 1 fail
 *     有 1 项未通过，先看上面标 FAIL 的项。
 *
 * 几个必须照抄的细节：
 *   - 行首是 `[ OK ]`（" OK " 带空格）与 `[FAIL]`（无空格），不是统一格式；
 *   - 有失败时**退出码是 2**，不是 1；
 *   - perf_event_open 这项原件会拿到 E2BIG（errno=7）——它用 sizeof(perf_event_attr)
 *     传给 6.18 内核，超出可接受尺寸。这里照实复现，WorkflowEngine 里另有
 *     perf_slide 复核来覆盖这条已知误报。
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

static void ok_line(const char *name, const char *detail)
{
	g_ok++;
	printf("  [ OK ] %-40s %s\n", name, detail ? detail : "");
}

static void fail_line(const char *name, const char *detail)
{
	g_fail++;
	printf("  [FAIL] %-40s %s\n", name, detail ? detail : "");
}

static void check_open(const char *label, const char *path, int flags, const char *okDetail)
{
	int fd = open(path, flags | O_CLOEXEC);
	if (fd < 0) {
		char detail[160];
		snprintf(detail, sizeof(detail), "errno=%d (%s)", errno, strerror(errno));
		fail_line(label, detail);
		return;
	}
	close(fd);
	ok_line(label, okDetail);
}

static void check_write(const char *label, const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		char detail[160];
		snprintf(detail, sizeof(detail), "errno=%d (%s)", errno, strerror(errno));
		fail_line(label, detail);
		return;
	}
	ssize_t n = write(fd, value, strlen(value));
	close(fd);
	if (n != (ssize_t)strlen(value)) {
		char detail[160];
		snprintf(detail, sizeof(detail), "write errno=%d", errno);
		fail_line(label, detail);
		return;
	}
	ok_line(label, "write ok");
}

static void capture(const char *command, char *out, size_t len)
{
	out[0] = '\0';
	FILE *pipe = popen(command, "r");
	if (!pipe)
		return;
	size_t used = 0;
	if (fgets(out, (int)len, pipe) != NULL)
		used = strlen(out);
	while (used > 0 && (out[used - 1] == '\n' || out[used - 1] == '\r'))
		out[--used] = '\0';
	pclose(pipe);
}

/* 原件把 sizeof(struct perf_event_attr) 传给内核，6.18 会返回 E2BIG —— 照实复现。 */
static int perf_event_open_software(void)
{
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_SOFTWARE;
	attr.size = sizeof(attr);
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
	char value[256];
	char detail[160];

	printf("=== CVE-2026-98260 / lhasa 环境诊断（重写版）===\n");

	capture("uname -r", value, sizeof(value));
	printf("  uname -r        : %s\n", value);

	capture("uname -v", value, sizeof(value));
	printf("  kernel version  : %s\n", value);

	capture("getprop ro.product.device", value, sizeof(value));
	printf("  ro.product.device: %s\n", value);

	capture("getprop ro.product.model", value, sizeof(value));
	printf("  ro.product.model : %s\n", value);

	capture("getprop ro.build.version.incremental", value, sizeof(value));
	printf("  系统增量         : %s\n", value);

	capture("getenforce", value, sizeof(value));
	printf("  getenforce      : %s\n", value);

	capture("id", value, sizeof(value));
	printf("  id              : %s\n", value);

	printf("\n--- 内核信息泄露面 ---\n");
	check_open("/proc/slabinfo 可读", "/proc/slabinfo", O_RDONLY, "open ok");
	check_open("/proc/kallsyms 可读", "/proc/kallsyms", O_RDONLY, "ok");

	int pagemap = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
	if (pagemap < 0) {
		snprintf(detail, sizeof(detail), "errno=%d (%s)", errno, strerror(errno));
		fail_line("/proc/self/pagemap", detail);
	} else {
		close(pagemap);
		ok_line("/proc/self/pagemap", "present=1");
	}

	printf("\n--- tracefs（决定整条链能否观测）---\n");
	check_open("/sys/kernel/tracing 存在", "/sys/kernel/tracing", O_RDONLY, "access");
	check_write("tracing_on 可写", "/sys/kernel/tracing/tracing_on", "1");
	check_write("kmem/rss_stat/trigger 可写",
	            "/sys/kernel/tracing/events/kmem/rss_stat/trigger",
	            "!enable_event:kmem:kmem_cache_alloc");
	check_open("kmem_cache_alloc/enable 可写",
	           "/sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable", O_WRONLY, "open ok");
	check_open("per_cpu/cpu0/trace_pipe_raw 可读",
	           "/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw",
	           O_RDONLY | O_NONBLOCK, "access");
	check_open("kprobe_events 存在", "/sys/kernel/tracing/kprobe_events", O_RDONLY, "access");

	printf("\n--- 系统调用面 ---\n");
	if (thread_timer() != 0) {
		snprintf(detail, sizeof(detail), "timer_create errno=%d", errno);
		fail_line("timer_create(CLOCK_THREAD_CPUTIME)", detail);
	} else {
		ok_line("timer_create(CLOCK_THREAD_CPUTIME)", "ok");
	}

	if (aio_setup_probe() != 0) {
		snprintf(detail, sizeof(detail), "errno=%d (%s)", errno, strerror(errno));
		fail_line("io_setup (AIO)", detail);
	} else {
		ok_line("io_setup (AIO)", "ok");
	}

	if (unix_stream_8k() != 0) {
		snprintf(detail, sizeof(detail), "socketpair errno=%d", errno);
		fail_line("unix SOCK_STREAM 8KB write", detail);
	} else {
		ok_line("unix SOCK_STREAM 8KB write", "ok");
	}

	int perf_fd = perf_event_open_software();
	if (perf_fd < 0) {
		snprintf(detail, sizeof(detail), "errno=%d (%s)", errno, strerror(errno));
		fail_line("perf_event_open (software)", detail);
	} else {
		close(perf_fd);
		ok_line("perf_event_open (software)", "ok");
	}

	printf("\n--- 结论 ---\n");
	printf("  %d ok / %d fail\n", g_ok, g_fail);
	if (g_fail == 0) {
		printf("  必需项全部通过\n");
		return 0;
	}
	printf("  有 %d 项未通过，先看上面标 FAIL 的项。\n", g_fail);
	return 2;
}
