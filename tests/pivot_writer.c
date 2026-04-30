#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int join_path(char out[PATH_MAX], const char *base, const char *name)
{
	size_t base_len = strlen(base);
	size_t name_len = strlen(name);

	if (base_len + 1 + name_len + 1 > PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}

	memcpy(out, base, base_len);
	out[base_len] = '/';
	memcpy(out + base_len + 1, name, name_len);
	out[base_len + 1 + name_len] = '\0';
	return 0;
}

static int mkdir_ok(const char *path)
{
	if (mkdir(path, 0755) == 0 || errno == EEXIST)
		return 0;
	return -1;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s ROOT\n", argv[0]);
		return 2;
	}

	char root[PATH_MAX];
	if (!realpath(argv[1], root)) {
		perror("realpath");
		return 1;
	}

	if (unshare(CLONE_NEWNS) < 0) {
		perror("unshare(CLONE_NEWNS)");
		return 1;
	}
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
		perror("mount MS_PRIVATE");
		return 1;
	}

	char tmp[PATH_MAX];
	char oldroot[PATH_MAX];
	if (join_path(tmp, root, "tmp") < 0) {
		perror("tmp path");
		return 1;
	}
	if (join_path(oldroot, root, "oldroot") < 0) {
		perror("oldroot path");
		return 1;
	}
	if (mkdir_ok(tmp) < 0) {
		perror("mkdir tmp");
		return 1;
	}
	if (mkdir_ok(oldroot) < 0) {
		perror("mkdir oldroot");
		return 1;
	}

	if (syscall(SYS_pivot_root, root, oldroot) < 0) {
		perror("pivot_root");
		return 1;
	}
	if (chdir("/") < 0) {
		perror("chdir /");
		return 1;
	}
	if (umount2("/oldroot", MNT_DETACH) < 0) {
		perror("umount oldroot");
		return 1;
	}
	if (rmdir("/oldroot") < 0) {
		perror("rmdir oldroot");
		return 1;
	}

	int fd = open("/tmp/marker", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		perror("open /tmp/marker");
		return 1;
	}
	const char payload[] = "pivot marker\n";
	if (write(fd, payload, sizeof payload - 1) != (ssize_t)sizeof payload - 1) {
		perror("write /tmp/marker");
		close(fd);
		return 1;
	}
	if (close(fd) < 0) {
		perror("close /tmp/marker");
		return 1;
	}

	return 0;
}
