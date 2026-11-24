/*
 * c99491_agent —— 被 ctest 改造 cred 的进程，负责落地 KernelSU。
 *
 * 已实测确认：
 *   1. cred 改写后 Uid: 0 0 2000 0，且 CapInh/CapPrm/CapEff/CapBnd 均为
 *      0x0e00050000（含 CAP_SYSLOG=34 / CAP_SYS_MODULE=16）；
 *   2. 真实 uid=0 且 permitted 非空时 execve 走 legacy 语义 E'=P'，
 *      能力可跨 exec 保留（本版本依赖这一点）；
 *   3. SELinux permissive 只放行策略检查，不授予能力；把 selinux_state+0
 *      清零可打开窗口（enforce 变 0，且能写回 1）；
 *   4. 自己 finit_module 提取的 ksu.ko 返回 ENOENT（未做符号重定位），
 *      因此改由 ksud（它会读 kallsyms 重定位）执行。
 *
 * 本版本重点：把 ksud 的 stdout/stderr 通过**管道**捕获后写进本日志，
 * 避免之前 dup2 到文件失败导致的“报错丢失”。
 *
 * 日志：/data/local/tmp/c99491_agent.log
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

/* 只取本次新增的 kmsg，且最多 12 行 */
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
			    strstr(p, "insmod") || strstr(p, "finit") ||
			    strstr(p, "avc"))
				fprintf(f, "  %s\n", p), kept++;
			p = nl + 1;
		}
	}
	close(fd);
}

/* 用管道捕获 ksud 输出，再写进我们自己的日志（不依赖目标目录可写） */
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
		fflush(f);
	}
	close(pipefd[0]);
	waitpid(p, &st, 0);
	fprintf(f, "ksud %s exit=%d\n", tag, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
	fflush(f);
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
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
