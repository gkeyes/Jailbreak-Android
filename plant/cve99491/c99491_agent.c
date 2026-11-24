/*
 * c99491_agent —— 被 ctest 改造 cred 的那个进程，原地完成 KernelSU 落地。
 *
 * 已证实的结论（本机实测）：
 *   - cred 改写后 euid=0、CapEff=0x0e00050000，但 permitted 为空；
 *   - 不带 permissive 时 finit_module 返回 EPERM，AVC 明确写：
 *       avc: denied { sys_module } capability=16 scontext=u:r:shell:s0
 *     → SELinux 的 capability 类规则不允许 shell 域使用 CAP_SYS_MODULE；
 *   - 打开 permissive 窗口后同一调用返回 EEXIST（模块已存在），
 *     证明权限门禁已通过、请求真的进入了内核。
 *
 * 因此流程：
 *   1. 等 ctest 改好 cred（euid==0 且 CapEff 含 CAP_SYS_MODULE）
 *   2. 等 permissive 窗口（ctest 以 C99491_PERMISSIVE=1 打开）
 *   3. finit_module(/data/local/tmp/ksu.ko, "allow_shell=1")
 *   4. 成功则 fork+exec `ksud late-load`，让官方工具完成 install/features/
 *      策略与管理器拉起（此时进程 uid=0，且能力位已在 permitted/ambient 里）
 *   5. 恢复 Enforcing 并记录状态
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

/* 官方工具收尾：ksud late-load 会跳过 KO 加载，只做 install/features/策略/管理器 */
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
}

int main(void)
{
	FILE *f = fopen(LOG_PATH, "w");
	int fd, ready = 0, perm = 0, rc, saved;
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
	fflush(f);

	if (stat(KO_PATH, &st) != 0) {
		fprintf(f, "=== abort: 缺少 %s (errno=%d) ===\n", KO_PATH, errno);
		fclose(f);
		return 3;
	}
	fprintf(f, "ko size=%ld\n", (long)st.st_size);

	fd = open(KO_PATH, O_RDONLY);
	if (fd < 0) {
		fprintf(f, "open ko failed errno=%d\n", errno);
		fclose(f);
		return 4;
	}
	errno = 0;
	rc = (int)syscall(SYS_finit_module, fd, "allow_shell=1", 0);
	saved = errno;
	fprintf(f, "finit_module rc=%d errno=%d (%s)\n", rc, saved, strerror(saved));
	close(fd);
	fflush(f);

	/* 模块已就绪（rc==0，或 EEXIST 表示本 boot 已加载）→ 用 ksud 收尾 */
	if (rc == 0 || saved == EEXIST)
		run_ksud(f);

	if (perm && set_enforce(1) != 0)
		fprintf(f, "restore enforce failed errno=%d\n", errno);
	fprintf(f, "enforce_after=%d\n", enforce_state());
	fprintf(f, "su_exists=%d\n", access("/system/bin/su", X_OK) == 0);
	fprintf(f, "=== done ===\n");
	fclose(f);
	return 0;
}
