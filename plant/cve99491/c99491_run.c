/*
 * c99491_run —— 被 agent 直接 exec 的静态 runner（避开 mksh 的降权）。
 *
 * 为什么需要它：
 *   Android 的 /system/bin/sh 是 mksh，启动时若发现 euid != uid，会主动
 *   setuid(getuid()) 把有效 uid 降回去（防 setuid 脚本）。实测 agent 的
 *   euid 已是 0、能力位也在，但 `run ksud_go.sh` 出来的 sh 里 Uid 全 2000。
 *   所以必须不经 shell，直接 exec 一个二进制，uid/caps 才不会被清。
 *
 * 它做三件事：
 *   1. 记录自身 uid/euid/gid/egid 与 Cap*（证明 exec 后凭据保留情况）
 *   2. 用 fd=-1 调 finit_module，判断 Module 加载被哪一层挡住：
 *        EPERM  -> 能力位不足
 *        EACCES -> SELinux 拦截
 *        EBADF  -> 能力与策略都通过（只是 fd 无效），可以真正装模块
 *   3. 直接 execv ksud late-load（不经过 shell），结果追加到同一个日志
 *
 * 日志：/data/local/tmp/c99491_run.log
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_PATH "/data/local/tmp/c99491_run.log"
#define KSUD "/data/local/tmp/ksud"

static void dump_status(FILE *f)
{
	char line[512];
	FILE *s = fopen("/proc/self/status", "r");

	fprintf(f, "uid=%d euid=%d gid=%d egid=%d\n",
		(int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid());
	if (!s) {
		fprintf(f, "(no /proc/self/status)\n");
		return;
	}
	while (fgets(line, sizeof(line), s)) {
		if (!strncmp(line, "Uid:", 4) || !strncmp(line, "Gid:", 4) ||
		    !strncmp(line, "CapInh:", 7) || !strncmp(line, "CapPrm:", 7) ||
		    !strncmp(line, "CapEff:", 7) || !strncmp(line, "CapBnd:", 7) ||
		    !strncmp(line, "CapAmb:", 7))
			fputs(line, f);
	}
	fclose(s);
}

int main(void)
{
	FILE *f = fopen(LOG_PATH, "w");
	long rc;
	int saved;
	pid_t p;
	int st = 0;

	if (!f)
		return 1;
	fprintf(f, "=== c99491_run %ld ===\n", (long)time(NULL) * 1L);

	dump_status(f);

	/* 模块加载门禁探测：fd=-1 时内核先查能力、再查安全策略、最后才碰 fd */
	errno = 0;
	rc = syscall(SYS_finit_module, -1, "", 0);
	saved = errno;
	fprintf(f, "finit_module(fd=-1) rc=%ld errno=%d (%s)\n",
		rc, saved, strerror(saved));
	if (saved == EPERM)
		fprintf(f, "verdict=caps_missing\n");
	else if (saved == EACCES)
		fprintf(f, "verdict=selinux_blocked\n");
	else
		fprintf(f, "verdict=gate_passed\n");

	/* 不经 shell，直接 exec ksud */
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
		execl(KSUD, KSUD, "late-load", "--kmi", "android17-6.18",
		      "--allow-shell", "--package-name", "me.weishu.kernelsu",
		      (char *)NULL);
		_exit(127);
	}
	if (p > 0) {
		waitpid(p, &st, 0);
		fprintf(f, "ksud exit=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
	} else {
		fprintf(f, "fork failed errno=%d\n", errno);
	}

	fprintf(f, "su exists=%d\n", access("/system/bin/su", X_OK) == 0);
	fprintf(f, "=== done ===\n");
	fclose(f);
	return 0;
}
