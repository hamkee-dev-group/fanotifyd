#ifndef FAN_PATH_H
#define FAN_PATH_H

#include <stddef.h>
#include <linux/fanotify.h>
#include <sys/fanotify.h>

struct daemon_cfg;








struct mount_entry {
	__kernel_fsid_t fsid;
	int             fd;
	char           *root;    
};

struct mount_db {
	struct mount_entry *entries;
	size_t              len;
	size_t              cap;
};

void mount_db_init(struct mount_db *db);
void mount_db_free(struct mount_db *db);





int  mount_db_add_for_path(struct mount_db *db, const char *path);

 
int  mount_db_lookup(const struct mount_db *db, const __kernel_fsid_t *fsid);

 
int  resolve_fd_path(int fd, char *out, size_t cap);





int  job_classify_path(const struct daemon_cfg *cfg, const char *path,
                       const char **job_id_out, const char **path_role_out);

#endif
