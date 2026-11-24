/*
 * c99491_agent —— 被 ctest 改造 cred 的那个进程，原地加载 KernelSU 模块。
 *
 * 设计动机（实测结论）：
 *   - agent 被改 cred 后有 euid=0、CapEff=0x0e00050000，但 CapPrm=0；
 *   - 只要 exec 一次，内核就按 permitted/ambient 重算，能力全部清空
 *     （实测 CapPrm/CapEff 归零）；
 *   - finit_module(fd=-1) 返回 EPERM 而不是 EACCES，说明缺的是能力位，
 *     不是 SELinux 策略。
 *   所以不要在子进程里调 shell 或工具，而是在**同一个进程内**直接用
 *   已经拿到的 effective 能力调 finit_module。
 *
 * 流程：
 *   1. 轮询 /proc/self/status，等 euid==0 且 CapEff 含 CAP_SYS_MODULE
 *   2. 打开 /data/local/tmp/ksu.ko（由 ksud 从管理器 APK 提取）
 *   3. finit_module(fd, "allow_shell=1", 0)
 *   4. 记录结果与 /sys/module/kernelsu 是否存在
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

static void dump(FILE *f, const char *tag)
{
	char line[256];
	FILE *s = fopen("/proc/self/status", "r");

	fprintf(f, "--- %s pid=%d ppid=%d ---\n", tag, (int)getpid(), (int)getppid());
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
	int fd, ready = 0;
	long rc;
	int saved;
	struct stat st;

	if (!f)
		return 1;
	fprintf(f, "=== c99491_agent start %ld ===\n", (long)time(NULL));
	dump(f, "start");
	fflush(f);

	/* 等 ctest 把 cred 改好：最多 30 秒 */
	for (int i = 0; i < 120; i++) {
		if (geteuid() == 0 && cap_sys_module()) {
			ready = 1;
			break;
		}
		usleep(250000);
	}
	fprintf(f, "ready=%d waited_ms=%d\n", ready, 0);
	dump(f, ready ? "patched" : "timeout");
	fflush(f);
	if (!ready) {
		fprintf(f, "=== abort: 凭据未落地 ===\n");
		fclose(f);
		return 2;
	}

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
	rc = syscall(SYS_finit_module, fd, "allow_shell=1", 0);
	saved = errno;
	fprintf(f, "finit_module rc=%ld errno=%d (%s)\n", rc, saved, strerror(saved));
	close(fd);

	fprintf(f, "module_kernelsu=%d\n", access("/sys/module/kernelsu", F_OK) == 0);
	fprintf(f, "su_exists=%d\n", access("/system/bin/su", X_OK) == 0);
	fprintf(f, "=== done ===\n");
	fclose(f);
	return 0;
}
