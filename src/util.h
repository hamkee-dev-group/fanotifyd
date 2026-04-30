#ifndef FAN_UTIL_H
#define FAN_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define UNUSED(x) (void)(x)

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

uint64_t monotonic_ms(void);
uint64_t realtime_ms(void);

 
char *abs_path(const char *p);

 
int set_cloexec(int fd);
int set_nonblock(int fd);

 
void rstrip_slash(char *p);

 
int read_proc_comm(pid_t pid, char *buf, size_t cap);

 
int read_proc_exe(pid_t pid, char *buf, size_t cap);

#endif
