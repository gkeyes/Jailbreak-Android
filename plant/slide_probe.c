/*
 * slide_probe — 用 tracefs 里的 kmem 事件把 KASLR 位移量测出来。
 *
 * 按原件字符串表重建（strings/slide_probe.orig.txt）。原件走的是 tracefs 触发器，
 * 不是草稿里那套自己造的采样：
 *
 *   /sys/kernel/tracing/tracing_on                                   开 trace
 *   /sys/kernel/tracing/buffer_size_kb                               放大 ring
 *   /sys/kernel/tracing/events/kmem/rss_stat/enable                  打开统计事件
 *   /sys/kernel/tracing/events/kmem/rss_stat/trigger
 *       "!enable_event:kmem:kmem_cache_alloc"   触发时顺带打开 slab 事件
 *       "!disable_event:kmem:kmem_cache_alloc"  收尾时关掉
 *   /sys/kernel/tracing/per_cpu/cpu%d/trace(_pipe_raw)               每 CPU 取原始事件
 *   /sys/kernel/tracing/trace                                        汇总视图
 *
 * 输出行（原样保留格式）：
 *   [slide] cpu%d %s
 *   [slide] lines=%d
 *   [slide] raw cpu%d bytes=%zu hits=%d
 *   [slide] raw cpu%d site=%#lx ptr=%#lx
 *   [slide] timer_create errno=%d
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

#define TRACING_ON      "/sys/kernel/tracing/tracing_on"
#define BUFFER_SIZE_KB  "/sys/kernel/tracing/buffer_size_kb"
#define RSS_ENABLE      "/sys/kernel/tracing/events/kmem/rss_stat/enable"
#define RSS_TRIGGER     "/sys/kernel/tracing/events/kmem/rss_stat/trigger"
#define TRACE_ALL       "/sys/kernel/tracing/trace"
#define PERCPU_TRACE    "/sys/kernel/tracing/per_cpu/cpu%d/trace"
#define PERCPU_RAW      "/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw"

#define ON_KMEM   "!enable_event:kmem:kmem_cache_alloc"
#define OFF_KMEM  "!disable_event:kmem:kmem_cache_alloc"

static int write_file(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t n = write(fd, value, strlen(value));
	close(fd);
	return n == (ssize_t)strlen(value) ? 0 : -1;
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

/* 从一行 trace 里抽 site=/ptr= 两个十六进制值。 */
static int parse_site_ptr(const char *line, unsigned long *site, unsigned long *ptr)
{
	const char *s = strstr(line, "site=0x");
	const char *p = strstr(line, "ptr=0x");
	if (!s || !p)
		return 0;
	*site = strtoul(s + 7, NULL, 16);
	*ptr = strtoul(p + 6, NULL, 16);
	return 1;
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
	int failures = 0;

	if (thread_timer() != 0) {
		printf("[slide] timer_create errno=%d\n", errno);
		failures++;
	}

	if (write_file(BUFFER_SIZE_KB, "4096") != 0) {
		printf("[slide] cpu%d %s\n", 0, "buffer_size_kb");
		failures++;
	}

	if (write_file(RSS_ENABLE, "1") != 0) {
		printf("[slide] cpu%d %s\n", 0, "rss_stat/enable");
		failures++;
	}

	if (write_file(RSS_TRIGGER, ON_KMEM) != 0) {
		printf("[slide] cpu%d %s\n", 0, "rss_stat/trigger");
		failures++;
	}

	if (write_file(TRACING_ON, "1") != 0) {
		printf("[slide] cpu%d %s\n", 0, "tracing_on");
		failures++;
	}

	/* 给内核一点时间攒事件，再读汇总视图。 */
	usleep(200 * 1000);

	int lines = 0;
	unsigned long last_site = 0, last_ptr = 0;
	int hits = 0;

	int fd = open(TRACE_ALL, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		char buffer[65536];
		ssize_t n;
		while ((n = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
			buffer[n] = '\0';
			char *save = NULL;
			for (char *line = strtok_r(buffer, "\n", &save); line;
			     line = strtok_r(NULL, "\n", &save)) {
				lines++;
				unsigned long site, ptr;
				if (parse_site_ptr(line, &site, &ptr)) {
					last_site = site;
					last_ptr = ptr;
					hits++;
				}
			}
		}
		close(fd);
	}
	printf("[slide] lines=%d\n", lines);

	/* 每 CPU 的原始视图，能读多少读多少。 */
	for (int cpu = 0; cpu < 8; cpu++) {
		char path[192];
		snprintf(path, sizeof(path), PERCPU_RAW, cpu);
		int rf = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (rf < 0) {
			snprintf(path, sizeof(path), PERCPU_TRACE, cpu);
			rf = open(path, O_RDONLY | O_CLOEXEC);
		}
		if (rf < 0)
			continue;
		char raw[65536];
		ssize_t got = read(rf, raw, sizeof(raw) - 1);
		close(rf);
		if (got <= 0)
			continue;
		raw[got] = '\0';
		int cpu_hits = 0;
		char *save = NULL;
		for (char *line = strtok_r(raw, "\n", &save); line;
		     line = strtok_r(NULL, "\n", &save)) {
			unsigned long site, ptr;
			if (parse_site_ptr(line, &site, &ptr)) {
				last_site = site;
				last_ptr = ptr;
				cpu_hits++;
			}
		}
		printf("[slide] raw cpu%d bytes=%zu hits=%d\n", cpu, (size_t)got, cpu_hits);
	}

	if (hits > 0 || last_site != 0) {
		printf("[slide] raw cpu%d site=%#lx ptr=%#lx\n", 0, last_site, last_ptr);
	}

	write_file(RSS_TRIGGER, OFF_KMEM);
	write_file(TRACING_ON, "0");

	if (failures != 0) {
		printf("必需接口不可用\n");
		return 1;
	}
	if (hits == 0) {
		printf("必需项全部通过\n");
		printf("提示：本次没有采到 site/ptr 样本（trace 为空或事件未触发）。\n");
	}
	return 0;
}
