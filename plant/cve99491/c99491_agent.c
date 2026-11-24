/*
 * c99491_agent —— 被 ctest 改造 cred 的进程，负责在 permissive 窗口内落地 KernelSU。
 *
 * 本机实测的三条结论：
 *   1. cred 改写后 euid=0（Uid: 0 0 2000 0）、CapEff=0x0e00050000，但 permitted 为空；
 *   2. 不开 permissive 时 finit_module 返回 EPERM，AVC 明确：
 *        avc: denied { sys_module } capability=16 scontext=u:r:shell:s0
 *      → SELinux capability 类规则不允许 shell 域使用 CAP_SYS_MODULE；
 *   3. 自己 finit_module 提取出来的 ksu.ko 返回 ENOENT（符号解析失败）——
 *      该 KO 需要符号重定位，而 ksud 自己会读 kallsyms 完成这一步。
 *
 * 所以最终流程：
 *   1. 等 ctest 改好 cred（euid==0 且 CapEff 含 CAP_SYS_MODULE）
 *   2. 等 permissive 窗口（ctest 以 C99491_PERMISSIVE=1 打开）
 *      —— permissive 下 SELinux 的 capable() 钩子放行，ksud 才能读 kallsyms 并加载；
 *   3. 直接 exec `ksud late-load --kmi android17-6.18 --allow-shell`，
 *      由官方工具完成 KO 重定位、install、features、策略与管理器拉起；
 *   4. 恢复 Enforcing 并记录最终状态。
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

static int cap_sys_module(void)
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
	return (eff & (1ULL << 16)) != 0;
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

static void run_ksud(FILE *f)
{
	pid_t p;
	int st = 0;

	fprintf(f, "--- ksud late-load ---\n");
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
		execl(KSUD, KSUD, "late-load", "--kmi", KMI, "--allow-shell",
		      "--package-name", "me.weishu.kernelsu", (char *)NULL);
		_exit(127);
	}
	if (p > 0) {
		waitpid(p, &st, 0);
		fprintf(f, "ksud exit=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
	} else {
		fprintf(f, "ksud fork failed errno=%d\n", errno);
	}
	fflush(f);
}

int main(void)
{
	FILE *f = fopen(LOG_PATH, "w");
	int ready = 0, perm = 0;
	struct stat st;

	if (!f)
		return 1;
	fprintf(f, "=== c99491_agent start %ld ===\n", (long)time(NULL));
	dump(f, "start");
	fflush(f);

	for (int i = 0; i < 200; i++) {
		if (geteuid() == 0 && cap_sys_module()) {
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
	if (stat(KO_PATH, &st) == 0)
		fprintf(f, "ko size=%ld (仅供参考，实际由 ksud 处理)\n", (long)st.st_size);
	fflush(f);

	if (!perm) {
		fprintf(f, "=== abort: permissive 窗口未打开 ===\n");
		fclose(f);
		return 3;
	}

	run_ksud(f);

	if (set_enforce(1) != 0)
		fprintf(f, "restore enforce failed errno=%d\n", errno);
	fprintf(f, "enforce_after=%d\n", enforce_state());
	fprintf(f, "su_exists=%d\n", access("/system/bin/su", X_OK) == 0);
	fprintf(f, "=== done ===\n");
	fclose(f);
	return 0;
}
