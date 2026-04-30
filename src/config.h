#ifndef FAN_CONFIG_H
#define FAN_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#include "fan.h"

struct job_entry {
	char *job_id;
	char *rootfs;
	char *workspace;
	char *exportdir;
	char *cachedir;
};





struct daemon_cfg {
	struct mark_spec *marks;
	size_t            n_marks;

	char            **canaries;      
	size_t            n_canaries;

	char             *out_path;      
	char             *socket_path;
	char             *hook_cmd;
	char             *pid_file;

	struct job_entry *jobs;
	size_t            n_jobs;

	uint32_t          burst_threshold;
	uint32_t          burst_window_ms;
	uint32_t          hook_cooldown_ms;

	int               foreground;
	int               want_perm;
	int               deny_on_alert;
	int               want_fid;
	int               verbose;        
};

void daemon_cfg_init(struct daemon_cfg *c);
void daemon_cfg_free(struct daemon_cfg *c);

 
int  daemon_cfg_load_file(struct daemon_cfg *c, const char *path);

 
int  daemon_cfg_add_mark(struct daemon_cfg *c, const char *path,
                         enum mark_type t, uint64_t mask);
int  daemon_cfg_add_canary(struct daemon_cfg *c, const char *pat);
struct job_entry *daemon_cfg_add_job(struct daemon_cfg *c, const char *job_id);
int  daemon_cfg_set_job_path(struct daemon_cfg *c, const char *job_id,
                             const char *role, const char *path);

 
int  daemon_cfg_parse_argv(struct daemon_cfg *c, int argc, char **argv);

void daemon_cfg_print_usage(const char *prog);

#endif
