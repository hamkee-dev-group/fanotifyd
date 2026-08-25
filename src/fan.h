#ifndef FAN_FAN_H
#define FAN_FAN_H

#include <linux/fanotify.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/fanotify.h>
#include <sys/types.h>

#include "path.h"

 
enum mark_type {
	MARK_INODE,        
	MARK_MOUNT,        
	MARK_FILESYSTEM,   
};

struct mark_spec {
	char           *path;
	enum mark_type  type;
	uint64_t        mask;        
	int             children;    
};

 
int fan_init(int *out_fd, int want_fid, int want_perm);
uint64_t fan_compute_mark_mask(const struct mark_spec *m, int want_fid,
                               int want_perm);
int fan_fid_reporting(int want_fid, int want_perm);
uint64_t fan_fid_only_events(void);
int fan_clear_marks(int fanfd);






int fan_mark(int fanfd, struct mount_db *db, const struct mark_spec *m,
             int want_fid, int want_perm);

int fan_is_perm_event(uint64_t mask);
int fan_respond(int fanfd, int event_fd, uint32_t response);










struct fan_event {
	uint64_t mask;
	pid_t    pid;
	int      had_fd;
	int      fd;          

	char     path[4096];   
	char     name[256];    
	int      is_dir;       
	int      is_perm;      
	int      requires_response;  
	int      from_overflow;
};





typedef void (*fan_event_cb)(const struct fan_event *ev, void *user);

int fan_drain(int fanfd, struct mount_db *db, fan_event_cb cb, void *user);

 
size_t fan_mask_str(uint64_t mask, char *out, size_t cap);

#endif
