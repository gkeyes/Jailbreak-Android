/*
 * pc98260-su — rootd 客户端。
 *
 * rootd 由 uaf_plant_replay 在提权后启动，监听 /data/local/tmp/pc98260-root.sock，
 * 输出 "[rootd] listening at %s pid=%d"。本程序只需把一条命令送过去，把回显原样吐出。
 *
 * 协议假设（需与原件比对验证）：单连接、单命令，命令以 \n 结尾，发送后 shutdown(SHUT_WR)，
 * 读至 EOF。这是这类小型 rootd 最常见的形态，也是本实现唯一可验证的形态。
 * 套接字路径可用环境变量 PC98260_ROOT_SOCK 或 -s 覆盖。
 */
#define _GNU_SOURCE 1
#include <errno.h>
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
	fprintf(stderr,
		"用法: %s [-s socket] -c command\n"
		"  -s socket   rootd 套接字路径（默认 %s）\n"
		"  -c command  在 rootd 侧执行的命令\n",
		argv0, DEFAULT_SOCKET);
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
	const char *socket_path = getenv("PC98260_ROOT_SOCK");
	const char *command = NULL;
	int opt;

	if (!socket_path || !*socket_path)
		socket_path = DEFAULT_SOCKET;

	while ((opt = getopt(argc, argv, "s:c:h")) != -1) {
		switch (opt) {
		case 's':
			socket_path = optarg;
			break;
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
		fprintf(stderr, "pc98260-su: socket: %s\n", strerror(errno));
		return 1;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(socket_path) >= sizeof(addr.sun_path)) {
		fprintf(stderr, "pc98260-su: 套接字路径过长\n");
		return 1;
	}
	strcpy(addr.sun_path, socket_path);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "pc98260-su: connect %s: %s\n", socket_path, strerror(errno));
		return 1;
	}

	if (write_all(fd, command, strlen(command)) < 0 || write_all(fd, "\n", 1) < 0) {
		fprintf(stderr, "pc98260-su: write: %s\n", strerror(errno));
		return 1;
	}
	shutdown(fd, SHUT_WR);

	char buffer[IO_BUFFER];
	for (;;) {
		ssize_t n = read(fd, buffer, sizeof(buffer));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "pc98260-su: read: %s\n", strerror(errno));
			return 1;
		}
		if (n == 0)
			break;
		if (fwrite(buffer, 1, (size_t)n, stdout) != (size_t)n)
			break;
	}
	fflush(stdout);
	return 0;
}
