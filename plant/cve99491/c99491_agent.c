/*
 * c99491_agent —— 被 ctest 改造 cred 的进程，负责在 permissive 窗口内落地 KernelSU。
 *
 * 本机实测结论链：
 *   1. cred 改写后 Uid: 0 0 2000 0、CapEff=0x0e00050000（含 CAP_SYSLOG/SYS_MODULE）；
 *   2. 不开 permissive 时 finit_module 返回 EPERM，AVC 明确：
 *        avc: denied { sys_module } capability=16 scontext=u:r:shell:s0
 *   3. 开 permissive 后，capability 检查放行；但自己 finit_module 提取的 ksu.ko
 *      返回 ENOENT（符号未重定位）；
 *   4. shell 身份下 `ksud insmod` 报 "Cannot parse kallsyms: Permission denied"
 *      —— ksud 需要 CAP_SYSLOG 才能读 kallsyms 做重定位。
 *
 * 因此最终做法：在「uid=0 + CapEff 含 SYSLOG/SYS_MODULE + permissive 窗口」这三者
 * 同时成立的进程里，依次执行：
 *   ksud insmod /data/local/tmp/ksu.ko     ← 带 kallsyms 访问地加载并重定位
 *   ksud late-load --kmi ... --allow-shell ← 模块 Live 后只做 install/features/策略
 * 然后恢复 Enforcing。
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

/* 依次执行一条 ksud 子命令，输出追加到日志 */
static void run_ksud(FILE *f, char *const argv[])
{
	pid_t p;
	int st = 0;

	fprintf(f, "--- ksud %s ---\n", argv[1]);
	fflush(f);
	p = fork();
	if (p == 0) {
		int fd = open(LOG_PATH, O_WRONLY | O_APPEND);

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
		fprintf(f, "ksud %s exit=%d\n", argv[1],
			WIFEXITED(st) ? WEXITSTATUS(st) : -1);
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

	/* 等 cred 落地：真实 uid=0 且 effective 里有 SYSLOG + SYS_MODULE */
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

	/* 1) 带 kallsyms 访问地加载模块（ksud 自己完成符号重定位） */
	{
		char *ins[] = { (char *)KSUD, (char *)"insmod", (char *)KO_PATH, NULL };

		run_ksud(f, ins);
	}

	/* 2) 模块 Live 后由官方工具做 install/features/策略/管理器 */
	{
		char *late[] = { (char *)KSUD, (char *)"late-load", (char *)"--kmi",
				 (char *)KMI, (char *)"--allow-shell", (char *)"--package-name",
				 (char *)"me.weishu.kernelsu", NULL };

		run_ksud(f, late);
	}

	if (set_enforce(1) != 0)
		fprintf(f, "restore enforce failed errno=%d\n", errno);
	fprintf(f, "enforce_after=%d\n", enforce_state());
	fprintf(f, "su_exists=%d\n", access("/system/bin/su", X_OK) == 0);
	fprintf(f, "=== done ===\n");
	fclose(f);
	return 0;
}
