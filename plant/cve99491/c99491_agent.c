/*
 * c99491_agent —— 被 ctest 改造 cred 的进程，负责落地 KernelSU。
 *
 * 关键结论（本机逐条实测）：
 *   1. cred 改写后 Uid: 0 0 2000 0、CapEff=0x0e00050000；
 *   2. SELinux permissive **不会授予 capability**：cap_capable() 与策略无关，
 *      所以只把 caps 写进 effective 不够 —— exec 出去的 ksud 依然 EPERM；
 *   3. exec 会按 permitted/ambient 重算，因此必须等 patch_full_caps 把
 *      **CapPrm** 也写进去（实测 ctest 的 caps 轮次里出现过 prm=1 amb=1）；
 *   4. 真实 uid=0 + permitted 非空时，exec 后 E'=P'（legacy 语义），
 *      ksud 才能拿到 CAP_SYSLOG(34) 读 kallsyms、CAP_SYS_MODULE(16) 装模块。
 *
 * 所以等待条件改为：uid==0 且 CapPrm 同时含 bit34 与 bit16。
 *
 * 输出：
 *   /data/local/tmp/c99491_agent.log     自身状态（kmsg 只取新增部分）
 *   /data/local/tmp/ksud_<cmd>.log       每条 ksud 命令的完整输出
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LOG_PATH "/data/local/tmp/c99491_agent.log"
#define KO_PATH "/data/local/tmp/ksu.ko"
#define KSUD "/data/local/tmp/ksud"
#define KMI "android17-6.18"

static unsigned long long read_caps(const char *key)
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

static int enforce_state(void)
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

static void dump(FILE *f, const char *tag)
{
	char line[256];
	FILE *s = fopen("/proc/self/status", "r");

	fprintf(f, "--- %s pid=%d ppid=%d enforce=%d ---\n",
		tag, (int)getpid(), (int)getppid(), enforce_state());
	if (!s)
		return;
	while (fgets(line, sizeof(line), s)) {
		if (!strncmp(line, "Uid:", 4) || !strncmp(line, "CapPrm:", 7) ||
		    !strncmp(line, "CapEff:", 7) || !strncmp(line, "CapInh:", 7) ||
		    !strncmp(line, "CapBnd:", 7) || !strncmp(line, "CapAmb:", 7))
			fputs(line, f);
	}
	fclose(s);
}

/* 只取本次运行新增的 kmsg，且只保留与模块相关的少量行 */
static void dump_kmsg(FILE *f, const char *tag)
{
	int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	char buf[4096];
	ssize_t n;
	int kept = 0;

	fprintf(f, "--- kmsg(%s) ---\n", tag);
	if (fd < 0) {
		fprintf(f, "open /dev/kmsg failed errno=%d\n", errno);
		return;
	}
	lseek(fd, 0, SEEK_END);
	while ((n = read(fd, buf, sizeof(buf) - 1)) > 0 && kept < 12) {
		char *p = buf, *nl;

		buf[n] = 0;
		while ((nl = strchr(p, '\n')) != NULL && kept < 12) {
			*nl = 0;
			if (strstr(p, "module") || strstr(p, "kernelsu") ||
			    strstr(p, "insmod") || strstr(p, "finit")) {
				fprintf(f, "%s\n", p);
				kept++;
			}
			p = nl + 1;
		}
	}
	close(fd);
}

static void run_ksud(FILE *f, const char *tag, char *const argv[])
{
	char out_path[128];
	pid_t p;
	int st = 0;

	snprintf(out_path, sizeof(out_path), "/data/local/tmp/ksud_%s.log", tag);
	fprintf(f, "--- ksud %s (out=%s) ---\n", tag, out_path);
	fflush(f);
	p = fork();
	if (p == 0) {
		int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);

		if (fd >= 0) {
			dup2(fd, 1);
			dup2(fd, 2);
			if (fd > 2)
				close(fd);
		}
		execv(KSUD, argv);
		_exit(127);
	}
	if (p > 0) {
		waitpid(p, &st, 0);
		fprintf(f, "ksud %s exit=%d\n", tag, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
	}
	fflush(f);
}

int main(void)
{
	FILE *f = fopen(LOG_PATH, "w");
	int ready = 0;

	if (!f)
		return 1;
	fprintf(f, "=== c99491_agent start %ld ===\n", (long)time(NULL));
	dump(f, "start");
	fflush(f);

	/* 等 uid=0 且 CapPrm 含 SYSLOG(34) + SYS_MODULE(16) */
	for (int i = 0; i < 320; i++) {
		unsigned long long prm = read_caps("CapPrm:");

		if (getuid() == 0 && (prm & (1ULL << 34)) && (prm & (1ULL << 16))) {
			ready = 1;
			break;
		}
		usleep(250000);
	}
	fprintf(f, "ready=%d (需要 CapPrm 含 bit34+bit16)\n", ready);
	dump(f, ready ? "patched" : "timeout");
	fflush(f);
	if (!ready) {
		fprintf(f, "=== abort: permitted 能力未落地 ===\n");
		fclose(f);
		return 2;
	}

	{
		char *ins[] = { (char *)KSUD, (char *)"insmod", (char *)KO_PATH,
				(char *)"allow_shell=1", NULL };

		run_ksud(f, "insmod", ins);
	}
	dump_kmsg(f, "after-insmod");

	{
		char *late[] = { (char *)KSUD, (char *)"late-load", (char *)"--kmi",
				 (char *)KMI, (char *)"--allow-shell", (char *)"--package-name",
				 (char *)"me.weishu.kernelsu", NULL };

		run_ksud(f, "late-load", late);
	}

	fprintf(f, "restore_enforce rc=%d\n", set_enforce(1));
	fprintf(f, "enforce_after=%d\n", enforce_state());
	fprintf(f, "su_exists=%d\n", access("/system/bin/su", X_OK) == 0);
	fprintf(f, "=== done ===\n");
	fclose(f);
	return 0;
}
