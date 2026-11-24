/*
 * c99491_agent —— 被 ctest 改造 cred 的进程，负责落地 KernelSU。
 *
 * 关键约束（实测）：清零 selinux_state 前 8 字节会同时清掉
 * enforcing / initialized / policycap。permissive 打开后系统还能活几十秒，
 * 但窗口持续 1–3 分钟就会卡死或重启。上游做法是「窗口只覆盖一次
 * finit_module」。因此本版本把窗口压缩到 ~1 秒：
 *   等 cred 就绪 → 等窗口 → ksud insmod → 立刻恢复 Enforcing → 再 late-load
 *
 * 其余实测结论：
 *   - SELinux permissive 不授予能力，cap_capable() 独立于策略；
 *     因此必须等 CapPrm 含 SYSLOG(34)+SYS_MODULE(16) 再 exec，能力才可跨 exec；
 *   - 自己直接 finit_module 提取的 ksu.ko 会 ENOENT（未重定位），必须由 ksud 做；
 *   - ksud 输出用管道捕获后写入本日志（不依赖子进程写文件）。
 *
 * 日志：/data/local/tmp/c99491_agent.log（关键步骤 fsync，尽量留证）
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
	while ((n = read(fd, buf, sizeof(buf) - 1)) > 0 && kept < 10) {
		char *p = buf, *nl;

		buf[n] = 0;
		while ((nl = strchr(p, '\n')) != NULL && kept < 10) {
			*nl = 0;
			if (strstr(p, "module") || strstr(p, "kernelsu") ||
			    strstr(p, "insmod") || strstr(p, "finit")) {
				fprintf(f, "  %s\n", p);
				kept++;
			}
			p = nl + 1;
		}
	}
	close(fd);
}

static int run_ksud(FILE *f, const char *tag, char *const argv[])
{
	int pipefd[2];
	pid_t p;
	int st = 0;
	char buf[1024];
	ssize_t n;

	fprintf(f, "--- ksud %s ---\n", tag);
	fflush(f);
	if (pipe(pipefd) != 0) {
		fprintf(f, "pipe failed errno=%d\n", errno);
		return -1;
	}
	p = fork();
	if (p == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], 1);
		dup2(pipefd[1], 2);
		close(pipefd[1]);
		execv(KSUD, argv);
		fprintf(stderr, "execv failed errno=%d\n", errno);
		_exit(127);
	}
	close(pipefd[1]);
	if (p < 0) {
		close(pipefd[0]);
		fprintf(f, "fork failed errno=%d\n", errno);
		return -1;
	}
	while ((n = read(pipefd[0], buf, sizeof(buf) - 1)) > 0) {
		char *q = buf, *nl;

		buf[n] = 0;
		while ((nl = strchr(q, '\n')) != NULL) {
			*nl = 0;
			fprintf(f, "  [ksud %s] %s\n", tag, q);
			q = nl + 1;
		}
		if (*q)
			fprintf(f, "  [ksud %s] %s\n", tag, q);
	}
	close(pipefd[0]);
	waitpid(p, &st, 0);
	fprintf(f, "ksud %s exit=%d\n", tag, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
	fflush(f);
	fsync(fileno(f));
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int main(void)
{
	FILE *f = fopen(LOG_PATH, "w");
	int ready = 0, perm = 0, ins_rc = -1;

	if (!f)
		return 1;
	fprintf(f, "=== c99491_agent start %ld ===\n", (long)time(NULL));
	fflush(f);
	fsync(fileno(f));

	for (int i = 0; i < 320; i++) {
		unsigned long long prm = read_caps("CapPrm:");

		if (getuid() == 0 && (prm & (1ULL << 34)) && (prm & (1ULL << 16))) {
			ready = 1;
			break;
		}
		usleep(250000);
	}
	fprintf(f, "ready=%d (需要 uid=0 且 CapPrm 含 bit34+bit16)\n", ready);
	dump(f, ready ? "patched" : "timeout");
	fflush(f);
	fsync(fileno(f));
	if (!ready) {
		fprintf(f, "=== abort: permitted 能力未落地 ===\n");
		fclose(f);
		return 2;
	}

	for (int i = 0; i < 120; i++) {
		if (enforce_state() == 0) {
			perm = 1;
			break;
		}
		usleep(250000);
	}
	fprintf(f, "permissive_window=%d\n", perm);
	fflush(f);
	fsync(fileno(f));

	/* 窗口内只做一件事：ksud 读 kallsyms 重定位并 insmod */
	{
		char *ins[] = { (char *)KSUD, (char *)"insmod", (char *)KO_PATH,
				(char *)"allow_shell=1", NULL };

		ins_rc = run_ksud(f, "insmod", ins);
	}

	/* 立刻收窗：permissive 持续越久越容易挂 */
	fprintf(f, "restore_enforce rc=%d\n", set_enforce(1));
	fprintf(f, "enforce_after=%d\n", enforce_state());
	fflush(f);
	fsync(fileno(f));

	dump_kmsg(f, "after-insmod");

	{
		char *late[] = { (char *)KSUD, (char *)"late-load", (char *)"--kmi",
				 (char *)KMI, (char *)"--allow-shell", (char *)"--package-name",
				 (char *)"me.weishu.kernelsu", NULL };

		if (ins_rc == 0 || access("/sys/module/kernelsu", F_OK) == 0)
			run_ksud(f, "late-load", late);
		else
			fprintf(f, "skip late-load: insmod rc=%d\n", ins_rc);
	}

	fprintf(f, "su_exists=%d\n", access("/system/bin/su", X_OK) == 0);
	fprintf(f, "=== done ===\n");
	fflush(f);
	fclose(f);
	return 0;
}
