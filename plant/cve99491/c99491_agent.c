/*
 * c99491_agent —— 被 ctest 改造 cred 的那个进程，原地加载 KernelSU 模块。
 *
 * 设计动机（有硬证据）：
 *   - agent 被改 cred 后有 euid=0、CapEff=0x0e00050000，但 CapPrm=0；
 *   - exec 会按 permitted/ambient 重算，能力全清（实测 CapPrm/CapEff 归零）；
 *   - finit_module 返回 EPERM，AVC 明确写了
 *       avc: denied { sys_module } capability=16 scontext=u:r:shell:s0
 *     即 SELinux 的 capability 类规则不允许 shell 域用 CAP_SYS_MODULE。
 *
 * 因此流程改为：
 *   1. 轮询等 euid==0 且 CapEff 含 CAP_SYS_MODULE（ctest 改 cred 后即满足）
 *   2. 等 permissive 窗口（由 ctest 以 C99491_PERMISSIVE=1 打开）：
 *      轮询 /sys/fs/selinux/enforce 变为 0
 *   3. 打开 /data/local/tmp/ksu.ko 并 finit_module
 *   4. 立刻把 enforce 写回 1（本进程有 CAP_MAC_ADMIN），并记录结果
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
#include <time.h>
#include <unistd.h>

#define LOG_PATH "/data/local/tmp/c99491_agent.log"
#define KO_PATH "/data/local/tmp/ksu.ko"

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
	return (eff & (1ULL << 16)) != 0; /* CAP_SYS_MODULE = 16 */
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

	/* 1) 等 ctest 把 cred 改好 */
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

	/* 2) 等 permissive 窗口（ctest 以 C99491_PERMISSIVE=1 打开） */
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

	/* 3) 立刻恢复 Enforcing（本进程有 CAP_MAC_ADMIN） */
	if (perm && set_enforce(1) != 0)
		fprintf(f, "restore enforce failed errno=%d\n", errno);
	fprintf(f, "enforce_after=%d\n", enforce_state());
	fprintf(f, "module_kernelsu=%d\n", access("/sys/module/kernelsu", F_OK) == 0);
	fprintf(f, "su_exists=%d\n", access("/system/bin/su", X_OK) == 0);
	fprintf(f, "=== done ===\n");
	fclose(f);
	return 0;
}
