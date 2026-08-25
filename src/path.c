#include "path.h"
#include "config.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#include <unistd.h>

void mount_db_init(struct mount_db *db)
{
	db->entries = NULL;
	db->len = db->cap = 0;
}

void mount_db_free(struct mount_db *db)
{
	for (size_t i = 0; i < db->len; i++) {
		if (db->entries[i].fd >= 0)
			close(db->entries[i].fd);
		free(db->entries[i].root);
	}
	free(db->entries);
	db->entries = NULL;
	db->len = db->cap = 0;
}

static int fsid_eq(const __kernel_fsid_t *a, const __kernel_fsid_t *b)
{
	return a->val[0] == b->val[0] && a->val[1] == b->val[1];
}

int mount_db_lookup(const struct mount_db *db, const __kernel_fsid_t *fsid)
{
	for (size_t i = 0; i < db->len; i++)
		if (fsid_eq(&db->entries[i].fsid, fsid))
			return db->entries[i].fd;
	return -1;
}

int mount_db_add_for_path(struct mount_db *db, const char *path)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		 
		char *copy = strdup(path);
		if (!copy)
			return -1;
		char *slash = strrchr(copy, '/');
		const char *dir = ".";
		if (slash) {
			if (slash == copy) {
				dir = "/";
			} else {
				*slash = '\0';
				dir = copy;
			}
		}
		fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		free(copy);
		if (fd < 0)
			return -1;
	}

	struct statfs sf;
	if (fstatfs(fd, &sf) < 0) {
		close(fd);
		return -1;
	}
	__kernel_fsid_t fsid;
	memcpy(&fsid, &sf.f_fsid, sizeof fsid);

	if (mount_db_lookup(db, &fsid) >= 0) {
		close(fd);
		return 0;
	}

	if (db->len == db->cap) {
		size_t cap = db->cap ? db->cap * 2 : 8;
		struct mount_entry *e = realloc(db->entries, cap * sizeof *e);
		if (!e) {
			close(fd);
			return -1;
		}
		db->entries = e;
		db->cap = cap;
	}
	db->entries[db->len].fsid = fsid;
	db->entries[db->len].fd = fd;
	db->entries[db->len].root = strdup(path);
	db->len++;
	return 0;
}

int resolve_fd_path(int fd, char *out, size_t cap)
{
	char link[64];
	snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
	ssize_t n = readlink(link, out, cap - 1);
	if (n < 0)
		return -1;
	out[n] = '\0';
	return 0;
}

static int path_matches_root(const char *root, const char *path)
{
	if (!root || !*root || !path || !*path)
		return 0;
	if (strcmp(root, "/") == 0)
		return path[0] == '/';

	size_t root_len = strlen(root);
	if (strncmp(path, root, root_len) != 0)
		return 0;
	return path[root_len] == '\0' || path[root_len] == '/';
}

int job_classify_path(const struct daemon_cfg *cfg, const char *path,
                      const char **job_id_out, const char **path_role_out)
{
	if (job_id_out)
		*job_id_out = NULL;
	if (path_role_out)
		*path_role_out = NULL;
	if (!cfg || !path || !*path)
		return 0;

	size_t best_len = 0;
	const char *best_job = NULL;
	const char *best_role = NULL;

	for (size_t i = 0; i < cfg->n_jobs; i++) {
		const struct job_entry *job = &cfg->jobs[i];
		struct {
			const char *path;
			const char *role;
		} roles[] = {
			{ job->rootfs, "rootfs" },
			{ job->workspace, "workspace" },
			{ job->exportdir, "export" },
			{ job->cachedir, "cache" },
		};

		for (size_t j = 0; j < sizeof roles / sizeof roles[0]; j++) {
			const char *root = roles[j].path;
			if (!path_matches_root(root, path))
				continue;
			size_t root_len = strlen(root);
			if (root_len > best_len) {
				best_len = root_len;
				best_job = job->job_id;
				best_role = roles[j].role;
			}
		}
	}

	if (!best_job || !best_role)
		return 0;
	if (job_id_out)
		*job_id_out = best_job;
	if (path_role_out)
		*path_role_out = best_role;
	return 1;
}
