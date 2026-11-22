/*
 * slide_probe — 用 tracefs 里的 kmem 事件观察 posix timer 的 slab 分配。
 *
 * 与原件同条件对比后修正（2026-11-22，shell 身份，同一台机）：
 *
 *   原件：  [slide] lines=15，其中 15 行都是 kmem_cache_alloc，
 *           含 name=posix_timers_cache bytes_req=384（它自己 timer_create 产生的）
 *   旧版：  [slide] lines=30，全是 rss_stat，kmem_cache_alloc 一行没有
 *
 * 差异根因是**顺序**：必须先开 tracefs 事件，再 timer_create，
 * 那条 posix_timers_cache 分配才落在观测窗口内。旧版把 timer_create 放在最前面，
 * 目标分配发生在开启之前，颗粒无收。
 *
 * 另外 lines 只统计 kmem_cache_* 行（原件口径），rss_stat 行不计数也不打印。
 *
 * 符号表版本标记 LINUX_2.6.39 与目标 slab 判定（posix_timers_cache / bytes_req=384）
 * 沿用原件。
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

static const char *KERNEL_SYMBOL_VERSION = "LINUX_2.6.39";
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

/* 原件只统计 kmem_cache_* 事件行。 */
static int is_kmem_line(const char *line)
{
	return strstr(line, "kmem_cache_alloc") != NULL
		|| strstr(line, "kmem_cache_free") != NULL;
}

static int is_target_line(const char *line)
{
	return strstr(line, TARGET_SLAB) != NULL || strstr(line, TARGET_SIZE_MARKER) != NULL;
}

/*
 * 目标分配的产生方式：在事件已开启之后创建并销毁一个 posix timer，
 * 内核就会走 alloc_posix_timer() → 分配 posix_timers_cache 对象。
 */
static int poke_timer(void)
{
	timer_t timer;
	struct sigevent sev;
	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGUSR1;
	if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &timer) != 0)
		return -errno;
	timer_delete(timer);
	return 0;
}

int main(void)
{
	int failures = 0;

	/* 1. 先把观测打开 */
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

	/* 2. 再制造目标分配（顺序不能反） */
	int poke = poke_timer();
	if (poke != 0) {
		printf("[slide] timer_create errno=%d\n", -poke);
		failures++;
	}
	usleep(200 * 1000);

	/* 3. 读汇总视图，只统计 kmem_cache_* 行 */
	int lines = 0;
	int target_hits = 0;
	uint64_t last_ptr = 0;

	int fd = open(TRACE_ALL, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		char buffer[262144];
		ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
		close(fd);
		if (n > 0) {
			buffer[n] = '\0';
			char *save = NULL;
			for (char *line = strtok_r(buffer, "\n", &save); line;
			     line = strtok_r(NULL, "\n", &save)) {
				if (line[0] == '#')
					continue;
				if (!is_kmem_line(line))
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

	/* 4. 逐 CPU 原始视图（原件同样会把 0 字节的 CPU 也列出来） */
	for (int cpu = 0; cpu < 8; cpu++) {
		char path[192];
		snprintf(path, sizeof(path), PERCPU_RAW, cpu);
		int rf = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (rf < 0) {
			snprintf(path, sizeof(path), PERCPU_TRACE, cpu);
			rf = open(path, O_RDONLY | O_CLOEXEC);
		}
		if (rf < 0) {
			printf("[slide] raw cpu%d bytes=0 hits=0\n", cpu);
			continue;
		}
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
		/* 只报实际读到的哈希化指针；真正的 site（内核地址）需要符号表权限，不臆造。 */
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
