/*
 * pc98260-su — rootd 客户端。
 *
 * 原件字符串表（从 assets/pc98260-su 读出的全部数据段字符串）：
 *   "connect root daemon"                连接阶段给用户看的提示
 *   "/data/local/tmp/pc98260-root.sock"  rootd 监听的套接字
 *   "PC98260_SOCK"                       覆盖套接字的环境变量
 *   "usage: %s [-c command]\n"           用法行（只有 -c）
 *   "/dev/null"                          静默重定向用
 *
 * 本实现按这些锚点逐条对齐，不再自己发明选项：没有 -s，环境变量是 PC98260_SOCK
 * 而不是 PC98260_ROOT_SOCK，用法行也必须是原件那一条。
 *
 * 协议（与 rootd 侧对应）：单连接、单命令，命令以 \n 结尾，shutdown(SHUT_WR) 后读至 EOF。
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define DEFAULT_SOCKET "/data/local/tmp/pc98260-root.sock"
#define IO_BUFFER 16384

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s [-c command]\n", argv0);
}

static int write_all(int fd, const char *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = write(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *socket_path = getenv("PC98260_SOCK");
	const char *command = NULL;
	int opt;

	if (!socket_path || !*socket_path)
		socket_path = DEFAULT_SOCKET;

	while ((opt = getopt(argc, argv, "c:h")) != -1) {
		switch (opt) {
		case 'c':
			command = optarg;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (!command || !*command) {
		usage(argv[0]);
		return 2;
	}

	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return 1;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(socket_path) >= sizeof(addr.sun_path)) {
		return 1;
	}
	strcpy(addr.sun_path, socket_path);

	/* 原件数据段里带 /dev/null：连接前把 stderr 静音，rootd 侧噪音不外泄。 */
	int nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (nullfd >= 0) {
		dup2(nullfd, STDERR_FILENO);
		close(nullfd);
	}

	/* 这条提示要在静音之前输出，用户才看得见。 */
	write(STDERR_FILENO, "connect root daemon\n", 20);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		return 1;
	}

	if (write_all(fd, command, strlen(command)) < 0 || write_all(fd, "\n", 1) < 0) {
		return 1;
	}
	shutdown(fd, SHUT_WR);

	char buffer[IO_BUFFER];
	for (;;) {
		ssize_t n = read(fd, buffer, sizeof(buffer));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return 1;
		}
		if (n == 0)
			break;
		if (fwrite(buffer, 1, (size_t)n, stdout) != (size_t)n)
			break;
	}
	fflush(stdout);
	close(fd);
	return 0;
}
