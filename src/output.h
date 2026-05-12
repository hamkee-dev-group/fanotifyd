#ifndef FAN_OUTPUT_H
#define FAN_OUTPUT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "buf.h"

#define FAN_EVENT_SCHEMA_VERSION 1

#define OUT_MAX_SUBSCRIBERS 64









struct out_sink {
	int    file_fd;         
	int    listen_fd;       
	int   *sub_fds;         
	size_t sub_len;
	size_t sub_cap;
	char  *socket_path;     
	struct buf scratch;     
};

void out_init(struct out_sink *o);
void out_free(struct out_sink *o);

int  out_open_file(struct out_sink *o, const char *path);    
int  out_open_socket(struct out_sink *o, const char *path);  

 
int  out_emit_line(struct out_sink *o, const char *line, size_t len);



int  out_emit_event_line(struct out_sink *o,
                         uint64_t ts_ms, uint64_t mask,
                         const char *mask_str,
                         pid_t pid, const char *comm,
                         const char *exe, const char *path,
                         const char *name, int is_dir,
                         const char *job_id, const char *path_role,
                         const char *decision);

 
int  out_emit_alert_line(struct out_sink *o,
                         uint64_t ts_ms, const char *kind,
                         pid_t pid, const char *comm,
                         const char *exe, const char *path,
                         const char *reason, const char *extra_kv);

 
int  out_accept(struct out_sink *o);

 
static inline int out_listen_fd(const struct out_sink *o) { return o->listen_fd; }

#endif
