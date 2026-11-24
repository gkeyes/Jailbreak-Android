/*
 * c99491_agent —— 被 ctest 改造 cred 的进程，负责在 permissive 窗口内落地 KernelSU。
 *
 * 本机实测结论链：
 *   1. cred 改写后 Uid: 0 0 2000 0、CapEff=0x0e00050000（含 CAP_SYSLOG/SYS_MODULE）；
 *   2. 不开 permissive 时 finit_module 返回 EPERM（AVC：denied { sys_module }）；
 *   3. permissive 下自行 finit_module 提取的 KO 返回 ENOENT（符号未重定位）；
 *   4. shell 身份 `ksud insmod` 报 Cannot parse kallsyms（需要 CAP_SYSLOG）；
 *   5. uid=0 + caps + permissive 的 agent 里 `ksud insmod` 仍返回 EPERM ——
 *      具体原因需要内核日志，因此本版本增加 /dev/kmsg 抓取与独立输出文件。
 *
 * 输出：
 *   /data/local/tmp/c99491_agent.log   自身状态与流程
 *   /data/local/tmp/ksud_<cmd>.log     每条 ksud 命令的完整 stdout/stderr
 *   agent 日志内附 kmsg 中与 module/avc 相关的最近记录
 *
 * 日志：见上。
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

static int cap_bit(int bit)
{
	char line[256];
	FILE *s = fopen("/proc/self/status", "r");
	unsigned long long eff = 0;

	if (!s)
		return 0;
	while (fgets(line, sizeof(line), s)) {
		if (!strncmp(line, "CapEff:", 7)) {
			sscanf(line + 7, "%llx", &eff);
			break;
		}
	}
	fclose(s);
	return (eff & (1ULL << bit)) != 0;
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

/* 把 /dev/kmsg 中与模块/SELinux 相关的最近若干行写入日志 */
static void dump_kmsg(FILE *f, const char *tag)
{
	int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	char buf[8192];
	ssize_t n;

	fprintf(f, "--- kmsg(%s) ---\n", tag);
	if (fd < 0) {
		fprintf(f, "open /dev/kmsg failed errno=%d\n", errno);
		return;
	}
	/* 只读尾部：持续读到没有更多数据 */
	while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
		char *p = buf, *nl;

		buf[n] = 0;
		while ((nl = strchr(p, '\n')) != NULL) {
			*nl = 0;
			if (strstr(p, "module") || strstr(p, "avc") || strstr(p, "kernelsu"))
				fprintf(f, "%s\n", p);
			p = nl + 1;
		}
	}
	close(fd);
}

/* 执行一条 ksud 子命令；输出写入独立文件，避免与主日志交错丢失 */
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
	} else {
		fprintf(f, "ksud fork failed errno=%d\n", errno);
	}
	fflush(f);
}

int main(void)
{
	FILE *f = fopen(LOG_PATH, "w");
	int ready = 0, perm = 0;

	if (!f)
		return 1;
	fprintf(f, "=== c99491_agent start %ld ===\n", (long)time(NULL));
	dump(f, "start");
	fflush(f);

	for (int i = 0; i < 240; i++) {
		if (getuid() == 0 && cap_bit(34) && cap_bit(16)) {
			ready = 1;
			break;
		}
		usleep(250000);
	}
	fprintf(f, "ready=%d\n", ready);
	dump(f, ready ? "patched" : "timeout");
	fflush(f);
	if (!ready) {
		fprintf(f, "=== abort: 凭据未落地 ===\n");
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
	if (!perm) {
		fprintf(f, "=== abort: permissive 窗口未打开 ===\n");
		fclose(f);
		return 3;
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
	dump_kmsg(f, "after-late");

	fprintf(f, "restore_enforce rc=%d\n", set_enforce(1));
	fprintf(f, "enforce_after=%d\n", enforce_state());
	fprintf(f, "su_exists=%d\n", access("/system/bin/su", X_OK) == 0);
	fprintf(f, "=== done ===\n");
	fclose(f);
	return 0;
}
