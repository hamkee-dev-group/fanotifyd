#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

uint64_t monotonic_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}

uint64_t realtime_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}

char *abs_path(const char *p)
{
	if (!p || !*p)
		return NULL;
	char *r = realpath(p, NULL);
	if (r)
		return r;
	if (errno == ENOENT) {
		 
		if (p[0] == '/')
			return strdup(p);
		char cwd[PATH_MAX];
		if (!getcwd(cwd, sizeof cwd))
			return NULL;
		size_t n = strlen(cwd) + 1 + strlen(p) + 1;
		char *out = malloc(n);
		if (!out)
			return NULL;
		snprintf(out, n, "%s/%s", cwd, p);
		return out;
	}
	return NULL;
}

int set_cloexec(int fd)
{
	int flags = fcntl(fd, F_GETFD);
	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0 ? -1 : 0;
}

int set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ? -1 : 0;
}

void rstrip_slash(char *p)
{
	if (!p)
		return;
	size_t n = strlen(p);
	while (n > 1 && p[n - 1] == '/')
		p[--n] = '\0';
}

static ssize_t read_small_file(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, cap - 1);
	int e = errno;
	close(fd);
	errno = e;
	if (n < 0)
		return -1;
	buf[n] = '\0';
	return n;
}

int read_proc_comm(pid_t pid, char *buf, size_t cap)
{
	if (cap < 2)
		return -1;
	char path[64];
	snprintf(path, sizeof path, "/proc/%d/comm", (int)pid);
	ssize_t n = read_small_file(path, buf, cap);
	if (n < 0)
		return -1;
	 
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';
	return 0;
}

int read_proc_exe(pid_t pid, char *buf, size_t cap)
{
	char path[64];
	snprintf(path, sizeof path, "/proc/%d/exe", (int)pid);
	ssize_t n = readlink(path, buf, cap - 1);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	return 0;
}
