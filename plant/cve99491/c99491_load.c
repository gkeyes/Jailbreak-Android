/*
 * c99491_load —— 单进程 KernelSU 模块加载器（B 方案核心）。
 *
 * 为什么不用 ksud：
 *   - `ksud insmod` 需要 exec 一个新的 Rust 进程，能力继承受 permitted/ambient
 *     约束，且它的报错不透明；
 *   - 我们自己 finit_module 又因 KO 的 225 个未定义符号未被内核导出而 ENOENT。
 * 因此这里**在本进程内**完成：解析 KO 的 symtab → 用离线表把未定义符号
 * 改成 SHN_ABS 且 st_value = 链接期地址 + slide → memfd → finit_module。
 *
 * 前提（由 ctest 完成）：
 *   - 本进程 cred 已被改写：uid==0 且 CapPrm 含 CAP_SYSLOG(34)+CAP_SYS_MODULE(16)；
 *   - permissive 窗口已打开（/sys/fs/selinux/enforce == 0）。
 *
 * 用法：c99491_load --slide 0x<slide> [--ko /data/local/tmp/ksu.ko]
 * 日志：/data/local/tmp/c99491_load.log（每步 fsync）
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "ksu_syms.h"

#define LOG_PATH "/data/local/tmp/c99491_load.log"
#define DEFAULT_KO "/data/local/tmp/ksu.ko"
#define SHN_UNDEF 0
#define SHN_ABS 0xfff1
#define SHT_SYMTAB 2

struct ehdr64 {
	unsigned char e_ident[16];
	unsigned short e_type, e_machine;
	unsigned int e_version;
	unsigned long long e_entry, e_phoff, e_shoff;
	unsigned int e_flags;
	unsigned short e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
		e_shstrndx;
};

struct shdr64 {
	unsigned int sh_name, sh_type;
	unsigned long long sh_flags, sh_addr, sh_offset, sh_size;
	unsigned int sh_link, sh_info;
	unsigned long long sh_addralign, sh_entsize;
};

struct sym64 {
	unsigned int st_name;
	unsigned char st_info, st_other;
	unsigned short st_shndx;
	unsigned long long st_value, st_size;
};

static FILE *g_log;

static void logf_(const char *fmt, ...)
{
	va_list ap;

	if (!g_log)
		return;
	va_start(ap, fmt);
	vfprintf(g_log, fmt, ap);
	va_end(ap);
	fflush(g_log);
	fsync(fileno(g_log));
}

static unsigned long long cap_of(const char *key)
{
	char line[256];
	FILE *s = fopen("/proc/self/status", "r");
	unsigned long long v = 0;

	if (!s)
		return 0;
	while (fgets(line, sizeof(line), s)) {
		if (!strncmp(line, key, strlen(key))) {
			sscanf(line + strlen(key), "%llx", &v);
			break;
		}
	}
	fclose(s);
	return v;
}

static int enforce_now(void)
{
	int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
	char c = 0;

	if (fd < 0)
		return -1;
	if (read(fd, &c, 1) != 1)
		c = 0;
	close(fd);
	return c == '0' ? 0 : 1;
}

static int set_enforce(int on)
{
	int fd = open("/sys/fs/selinux/enforce", O_WRONLY);
	int rc;

	if (fd < 0)
		return -1;
	rc = (int)write(fd, on ? "1" : "0", 1);
	close(fd);
	return rc == 1 ? 0 : -1;
}

int main(int argc, char **argv)
{
	const char *ko_path = DEFAULT_KO;
	unsigned long long slide = 0;
	unsigned char *img = NULL;
	struct stat st;
	int fd = -1, memfd = -1, rc, patched = 0, missing = 0;
	struct ehdr64 *eh;
	struct shdr64 *sh;
	struct sym64 *syms;
	char *strtab = NULL;
	size_t strsize = 0;

	g_log = fopen(LOG_PATH, "w");
	if (!g_log)
		return 1;
	logf_("=== c99491_load start %ld ===\n", (long)time(NULL));

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--slide") && i + 1 < argc)
			slide = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--ko") && i + 1 < argc)
			ko_path = argv[++i];
	}
	logf_("slide=%#llx ko=%s\n", slide, ko_path);

	/* 等 ctest 把 cred 改好 */
	for (int i = 0; i < 320; i++) {
		unsigned long long prm = cap_of("CapPrm:");

		if (getuid() == 0 && (prm & (1ULL << 34)) && (prm & (1ULL << 16)))
			break;
		usleep(250000);
	}
	logf_("uid=%d CapPrm=%#llx CapEff=%#llx\n", (int)getuid(),
	      cap_of("CapPrm:"), cap_of("CapEff:"));
	if (getuid() != 0 || !(cap_of("CapPrm:") & (1ULL << 16))) {
		logf_("=== abort: 凭据未就绪 ===\n");
		return 2;
	}

	/* 等 permissive 窗口 */
	for (int i = 0; i < 200; i++) {
		if (enforce_now() == 0)
			break;
		usleep(100000);
	}
	logf_("enforce(before load)=%d\n", enforce_now());

	fd = open(ko_path, O_RDONLY);
	if (fd < 0) {
		logf_("open ko failed errno=%d\n", errno);
		return 3;
	}
	if (fstat(fd, &st) != 0) {
		logf_("stat ko failed errno=%d\n", errno);
		return 4;
	}
	img = malloc((size_t)st.st_size);
	if (!img || read(fd, img, (size_t)st.st_size) != (ssize_t)st.st_size) {
		logf_("read ko failed\n");
		return 5;
	}
	close(fd);
	logf_("ko size=%ld\n", (long)st.st_size);

	eh = (struct ehdr64 *)img;
	if (memcmp(eh->e_ident, "\177ELF", 4) != 0) {
		logf_("not ELF\n");
		return 6;
	}
	sh = (struct shdr64 *)(img + eh->e_shoff);

	/* 找 SHT_SYMTAB 与其字符串表 */
	for (int i = 0; i < eh->e_shnum; i++) {
		if (sh[i].sh_type == SHT_SYMTAB) {
			syms = (struct sym64 *)(img + sh[i].sh_offset);
			int nsym = (int)(sh[i].sh_size / sizeof(struct sym64));

			strtab = (char *)(img + sh[sh[i].sh_link].sh_offset);
			strsize = (size_t)sh[sh[i].sh_link].sh_size;
			logf_("symtab=%d syms=%d strsize=%zu\n", i, nsym, strsize);

			for (int k = 1; k < nsym; k++) {
				const char *nm;
				unsigned long long addr = 0;

				if (syms[k].st_shndx != SHN_UNDEF)
					continue;
				if (syms[k].st_name >= strsize)
					continue;
				nm = strtab + syms[k].st_name;
				for (int m = 0; m < KSU_SYM_COUNT; m++) {
					if (!strcmp(nm, ksu_syms[m].name)) {
						addr = ksu_syms[m].addr;
						break;
					}
				}
				if (!addr) {
					missing++;
					if (missing <= 5)
						logf_("  miss: %s\n", nm);
					continue;
				}
				syms[k].st_shndx = SHN_ABS;
				syms[k].st_value = addr + slide;
				patched++;
			}
			break;
		}
	}
	logf_("patched=%d missing=%d\n", patched, missing);
	if (missing > 0) {
		logf_("=== abort: 有 %d 个符号未在表中 ===\n", missing);
		return 7;
	}

	/* memfd + finit_module（进程内，无 exec） */
	memfd = (int)syscall(SYS_memfd_create, "ksu", 0);
	if (memfd < 0) {
		logf_("memfd_create failed errno=%d\n", errno);
		return 8;
	}
	if (write(memfd, img, (size_t)st.st_size) != (ssize_t)st.st_size) {
		logf_("memfd write failed errno=%d\n", errno);
		return 9;
	}
	lseek(memfd, 0, SEEK_SET);

	errno = 0;
	rc = (int)syscall(SYS_finit_module, memfd, "allow_shell=1", 0);
	logf_("finit_module rc=%d errno=%d (%s)\n", rc, errno, strerror(errno));
	close(memfd);

	logf_("restore enforce rc=%d\n", set_enforce(1));
	logf_("enforce_after=%d\n", enforce_now());
	logf_("su_exists=%d\n", access("/system/bin/su", X_OK) == 0);
	logf_("=== done ===\n");
	fclose(g_log);
	return rc == 0 ? 0 : 10;
}
