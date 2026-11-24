/*
 * site_probe —— 测出 kmem 分配的 call_site 低 21 位（构建相关常量）。
 *
 * 用于 CVE-2026-99491 移植：上游按 `call_site & 0x1fffff` 过滤 cred 与
 * lsm blob 的分配记录，而这个值随内核构建变化，必须在新内核上实测。
 *
 * 只读：只打开 tracefs、触发一次 exec、读 ring buffer；不写内核内存。
 *
 * 用法：
 *   site_probe [-v] [--exec PATH] [--repeat N]
 *
 * 输出示例：
 *   [cred] site_low21=0x6c02c req=0xb8 name=cred
 *   [kmem] etype=0x13a site_low21=0x6c02c req=0xb8 name=cred
 *   [kmalloc] etype=0x... site_low21=0x... req=0x28
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TRACE "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"
#define RSS_ENABLE TRACE "/events/kmem/rss_stat/enable"
#define TRACING_ON TRACE "/tracing_on"
#define TRACE_BUF TRACE "/buffer_size_kb"
#define TRACE_CLEAR TRACE "/trace"
#define RAW_PATH TRACE "/per_cpu/cpu%d/trace_pipe_raw"

#define PAGE_SZ 4096UL
#define RAW_MAX (8U << 20)
#define MAX_KINDS 64

/* 6.18 kmem record 里我们关心的两个字段偏移（见 ring 布局注释） */
#define OFF_SITE 8
#define OFF_DESC 24
#define OFF_REQ_CACHE 32 /* kmem_cache_alloc: bytes_req */
#define OFF_REQ_KMALLOC 24 /* kmalloc: bytes_req */
#define ETYPE_CACHE_ALLOC 0x13a

struct kind {
	unsigned etype;
	unsigned low21;
	unsigned long long req;
	char name[24];
	int count;
};

static struct kind kinds[MAX_KINDS];
static int nkinds;

static int verbose;

static long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static unsigned u32le(const unsigned char *b)
{
	unsigned v;

	memcpy(&v, b, 4);
	return v;
}

static unsigned long long u64le(const unsigned char *b)
{
	unsigned long long v;

	memcpy(&v, b, 8);
	return v;
}

static int wr(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t want, got;

	if (fd < 0)
		return -1;
	want = (ssize_t)strlen(text);
	got = write(fd, text, (size_t)want);
	close(fd);
	return got == want ? 0 : -1;
}

static void record(unsigned etype, unsigned low21, unsigned long long req, const char *name)
{
	for (int i = 0; i < nkinds; i++) {
		if (kinds[i].etype == etype && kinds[i].low21 == low21 &&
		    kinds[i].req == req && !strncmp(kinds[i].name, name, sizeof(kinds[i].name))) {
			kinds[i].count++;
			return;
		}
	}
	if (nkinds >= MAX_KINDS)
		return;
	kinds[nkinds].etype = etype;
	kinds[nkinds].low21 = low21;
	kinds[nkinds].req = req;
	snprintf(kinds[nkinds].name, sizeof(kinds[nkinds].name), "%s", name);
	kinds[nkinds].count = 1;
	nkinds++;
}

/* ring 条目遍历；布局同 6.18 trace ring（type word + 紧凑条目） */
static void scan_ring(const unsigned char *b, size_t n, int self_pid)
{
	for (size_t base = 0; base + PAGE_SZ <= n; base += PAGE_SZ) {
		unsigned long long commit = u64le(b + base + 8);
		size_t o = base + 16, end = base + 16 + (size_t)commit;

		if (end > base + PAGE_SZ)
			end = base + PAGE_SZ;
		while (o + 4 <= end) {
			unsigned hdr = u32le(b + o), tl = hdr & 31;
			size_t total, elen;
			const unsigned char *p;
			unsigned etype, epid;
			unsigned long long site, req;
			unsigned d, noff, nlen;
			char name[24] = "";

			if (tl == 29) {
				if (!(hdr >> 5))
					break;
				total = 4 + u32le(b + o + 4);
			} else if (tl == 30 || tl == 31) {
				total = 8;
			} else if (tl == 0) {
				total = 4 + u32le(b + o + 4);
			} else {
				total = 4 + tl * 4;
			}
			if (total < 8 || o + total > end)
				break;
			p = b + o + (tl == 0 ? 8 : 4);
			elen = total - (size_t)(p - (b + o));
			etype = u32le(p) & 0xffff;
			epid = (unsigned)u32le(p + 4);
			if (epid == (unsigned)self_pid) {
				o += total;
				continue;
			}

			site = u64le(p + OFF_SITE);
			if (etype == ETYPE_CACHE_ALLOC && elen >= 61) {
				req = u64le(p + OFF_REQ_CACHE);
				d = u32le(p + OFF_DESC);
				noff = d & 0xffff;
				nlen = d >> 16;
				if (noff + nlen <= elen && nlen > 0 && nlen < sizeof(name))
					memcpy(name, p + noff, nlen);
			} else if (etype != ETYPE_CACHE_ALLOC && elen >= 48) {
				req = u64le(p + OFF_REQ_KMALLOC);
			} else {
				o += total;
				continue;
			}
			record(etype, (unsigned)(site & 0x1fffffUL), req, name);
			if (verbose)
				printf("[raw] etype=%#x site=%#llx low21=%#x req=%#llx name=%s\n",
				       etype, site, (unsigned)(site & 0x1fffffUL), req, name);
			o += total;
		}
	}
}

static int read_cpu(int cpu, unsigned char *buf, size_t *used)
{
	char path[128];
	int fd;
	ssize_t got;

	snprintf(path, sizeof(path), RAW_PATH, cpu);
	fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return -1;
	*used = 0;
	while (*used + PAGE_SZ < RAW_MAX) {
		got = read(fd, buf + *used, RAW_MAX - *used);
		if (got <= 0)
			break;
		*used += (size_t)got;
	}
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	const char *exec_path = "/system/bin/true";
	int repeat = 3, ncpu = 8;
	unsigned char *buf;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v"))
			verbose = 1;
		else if (!strcmp(argv[i], "--exec") && i + 1 < argc)
			exec_path = argv[++i];
		else if (!strcmp(argv[i], "--repeat") && i + 1 < argc)
			repeat = atoi(argv[++i]);
	}

	/* 打开 kmem 事件：只能经 rss_stat 的 trigger（shell 域对该文件可写） */
	wr(TRIGGER, "!enable_event:kmem:kmem_cache_alloc\n");
	wr(TRIGGER, "!enable_event:kmem:kmalloc\n");
	wr(TRACE_BUF, "8192\n");
	wr(TRACE_CLEAR, "0\n");
	if (wr(TRIGGER, "enable_event:kmem:kmem_cache_alloc\n"))
		printf("[!] 打开 kmem_cache_alloc 失败：%s\n", strerror(errno));
	if (wr(TRIGGER, "enable_event:kmem:kmalloc\n"))
		printf("[!] 打开 kmalloc 失败：%s\n", strerror(errno));
	wr(RSS_ENABLE, "1\n");
	wr(TRACING_ON, "1\n");

	buf = malloc(RAW_MAX);
	if (!buf) {
		printf("[!] out of memory\n");
		return 1;
	}

	for (int round = 0; round < repeat; round++) {
		pid_t pid = fork();

		if (pid == 0) {
			char *const av[] = { (char *)exec_path, NULL };
			execv(exec_path, av);
			_exit(127);
		}
		if (pid > 0)
			waitpid(pid, NULL, 0);
		usleep(40000);
	}

	wr(TRACING_ON, "0\n");

	for (int cpu = 0; cpu < ncpu; cpu++) {
		size_t used = 0;

		if (read_cpu(cpu, buf, &used) || used == 0)
			continue;
		scan_ring(buf, used, getpid());
	}

	free(buf);
	wr(TRIGGER, "!enable_event:kmem:kmem_cache_alloc\n");
	wr(TRIGGER, "!enable_event:kmem:kmalloc\n");
	wr(RSS_ENABLE, "0\n");

	printf("[site] 共 %d 种分配记录\n", nkinds);
	for (int i = 0; i < nkinds; i++) {
		const char *tag = "kmem";

		if (kinds[i].etype == ETYPE_CACHE_ALLOC)
			tag = "cache";
		printf("[site] %-5s etype=%#05x low21=%#07x req=%#04llx count=%d name=%s\n",
		       tag, kinds[i].etype, kinds[i].low21,
		       kinds[i].req, kinds[i].count, kinds[i].name);
		if (kinds[i].etype == ETYPE_CACHE_ALLOC && !strcmp(kinds[i].name, "cred"))
			printf("[cred] site_low21=%#x req=%#llx\n",
			       kinds[i].low21, kinds[i].req);
	}
	return 0;
}
