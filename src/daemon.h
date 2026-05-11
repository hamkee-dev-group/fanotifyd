#ifndef FAN_DAEMON_H
#define FAN_DAEMON_H

#include "config.h"

#include <signal.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

struct event_loop_syscalls {
	int (*signalfd)(int fd, const sigset_t *mask, int flags);
	int (*timerfd_create)(int clockid, int flags);
	int (*timerfd_settime)(int fd, int flags,
	                       const struct itimerspec *new_value,
	                       struct itimerspec *old_value);
	int (*epoll_create1)(int flags);
	int (*epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event);
};

extern const struct event_loop_syscalls daemon_default_syscalls;

int daemon_setup_event_loop(const struct event_loop_syscalls *sc,
                            const sigset_t *mask,
                            int fanfd, int listenfd,
                            int *sigfd_out, int *tickfd_out, int *ep_out);

int daemon_run(struct daemon_cfg *cfg);

#endif
