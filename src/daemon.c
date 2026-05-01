#include "daemon.h"
#include "buf.h"
#include "fan.h"
#include "log.h"
#include "output.h"
#include "path.h"
#include "policy.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

struct ctx {
	struct out_sink     *out;
	struct policy_state *policy;
	const struct daemon_cfg *cfg;
	int                  fanfd;
	uint64_t             stats_events;
	uint64_t             stats_overflow;
};

static void on_event(const struct fan_event *ev, void *user)
{
	struct ctx *c = user;
	c->stats_events++;
	if (ev->from_overflow) {
		c->stats_overflow++;
		out_emit_alert_line(c->out, realtime_ms(), "overflow",
		                    0, NULL, NULL, NULL,
		                    "fanotify queue overflowed", NULL);
		return;
	}

	char masks[256];
	fan_mask_str(ev->mask, masks, sizeof masks);

	char comm[64] = {0};
	char exe[1024] = {0};
	if (ev->pid > 0) {
		read_proc_comm(ev->pid, comm, sizeof comm);
		read_proc_exe(ev->pid, exe, sizeof exe);
	}

	const char *job_id = NULL;
	const char *path_role = NULL;
	job_classify_path(c->cfg, ev->path, &job_id, &path_role);

	struct policy_input pin = {
		.ts_ms = monotonic_ms(),
		.mask  = ev->mask,
		.pid   = ev->pid,
		.comm  = comm[0] ? comm : NULL,
		.exe   = exe[0] ? exe : NULL,
		.path  = ev->path,
	};
	uint32_t decision = policy_on_event(c->policy, &pin);
	const char *decision_str = "observe";
	if (ev->requires_response)
		decision_str = decision == FAN_DENY ? "deny" : "allow";

	out_emit_event_line(c->out, realtime_ms(),
	                    ev->mask, masks,
	                    ev->pid, comm[0] ? comm : NULL,
	                    exe[0] ? exe : NULL,
	                    ev->path, ev->name, ev->is_dir,
	                    job_id, path_role, decision_str);
	if (ev->requires_response) {
		if (fan_respond(c->fanfd, ev->fd, decision) < 0)
			log_warn("fanotify response failed for fd %d: %s",
			         ev->fd, strerror(errno));
		close(ev->fd);
	}
}

static int do_daemonize(const char *pid_file)
{
	pid_t pid = fork();
	if (pid < 0) return -1;
	if (pid > 0) _exit(0);
	if (setsid() < 0) return -1;
	pid = fork();
	if (pid < 0) return -1;
	if (pid > 0) _exit(0);
	chdir("/");
	int devnull = open("/dev/null", O_RDWR);
	if (devnull >= 0) {
		dup2(devnull, 0);
		dup2(devnull, 1);
		if (devnull > 2) close(devnull);
	}
	if (pid_file && *pid_file) {
		FILE *f = fopen(pid_file, "w");
		if (f) {
			fprintf(f, "%d\n", (int)getpid());
			fclose(f);
		}
	}
	return 0;
}

int daemon_run(struct daemon_cfg *cfg)
{
	if (cfg->n_marks == 0) {
		fprintf(stderr, "fanotifyd: no watch paths configured. "
		                "Use --watch or a config file.\n");
		return 2;
	}

	struct out_sink out;
	out_init(&out);
	if (out_open_file(&out, cfg->out_path) < 0) {
		log_err("failed to open output '%s': %s",
		        cfg->out_path ? cfg->out_path : "-", strerror(errno));
		out_free(&out);
		return 1;
	}
	if (cfg->socket_path && out_open_socket(&out, cfg->socket_path) < 0) {
		log_err("failed to bind socket '%s': %s",
		        cfg->socket_path, strerror(errno));
		out_free(&out);
		return 1;
	}

	struct policy_cfg pcfg = {
		.canaries        = cfg->canaries,
		.n_canaries      = cfg->n_canaries,
		.burst_threshold = cfg->burst_threshold,
		.burst_window_ms = cfg->burst_window_ms,
		.hook_cmd        = cfg->hook_cmd,
		.hook_cooldown_ms= cfg->hook_cooldown_ms,
		.deny_on_alert   = cfg->deny_on_alert,
	};
	struct policy_state *policy = policy_new(&pcfg, &out);
	if (!policy) {
		log_err("policy_new failed");
		out_free(&out);
		return 1;
	}

	int fanfd = -1;
	int use_fid = cfg->want_fid && !cfg->want_perm;
	if (cfg->want_perm && cfg->want_fid)
		log_warn("permission events require FD mode; disabling FID reporting");
	if (fan_init(&fanfd, use_fid, cfg->want_perm) < 0) {
		log_err("fanotify_init failed: %s", strerror(errno));
		log_err("(fanotifyd typically requires CAP_SYS_ADMIN; "
		        "try running as root or with appropriate capabilities)");
		policy_free(policy);
		out_free(&out);
		return 1;
	}

	struct mount_db mdb;
	mount_db_init(&mdb);

	for (size_t i = 0; i < cfg->n_marks; i++) {
		if (fan_mark(fanfd, &mdb, &cfg->marks[i],
		             use_fid, cfg->want_perm) < 0) {
			log_err("fanotify_mark(%s) failed: %s",
			        cfg->marks[i].path, strerror(errno));
			close(fanfd);
			mount_db_free(&mdb);
			policy_free(policy);
			out_free(&out);
			return 1;
		}
		log_info("watching %s (type=%d)",
		         cfg->marks[i].path, (int)cfg->marks[i].type);
	}

	 
	for (size_t i = 0; i < cfg->n_canaries; i++)
		mount_db_add_for_path(&mdb, cfg->canaries[i]);

	if (!cfg->foreground) {
		if (do_daemonize(cfg->pid_file) < 0) {
			log_err("daemonize failed: %s", strerror(errno));
			close(fanfd);
			mount_db_free(&mdb);
			policy_free(policy);
			out_free(&out);
			return 1;
		}
	} else if (cfg->pid_file && *cfg->pid_file) {
		FILE *f = fopen(cfg->pid_file, "w");
		if (f) {
			fprintf(f, "%d\n", (int)getpid());
			fclose(f);
		}
	}


	signal(SIGPIPE, SIG_IGN);

	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		log_err("sigprocmask: %s", strerror(errno));
		close(fanfd);
		mount_db_free(&mdb);
		policy_free(policy);
		out_free(&out);
		return 1;
	}
	int sigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);

	int tickfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	struct itimerspec ts = {
		.it_value    = { .tv_sec = 1 },
		.it_interval = { .tv_sec = 1 },
	};
	timerfd_settime(tickfd, 0, &ts, NULL);

	int ep = epoll_create1(EPOLL_CLOEXEC);
	struct epoll_event ee = { .events = EPOLLIN };
	ee.data.fd = fanfd; epoll_ctl(ep, EPOLL_CTL_ADD, fanfd, &ee);
	ee.data.fd = sigfd; epoll_ctl(ep, EPOLL_CTL_ADD, sigfd, &ee);
	ee.data.fd = tickfd; epoll_ctl(ep, EPOLL_CTL_ADD, tickfd, &ee);
	if (out_listen_fd(&out) >= 0) {
		ee.data.fd = out_listen_fd(&out);
		epoll_ctl(ep, EPOLL_CTL_ADD, out_listen_fd(&out), &ee);
	}

	struct ctx c = {
		.out = &out,
		.policy = policy,
		.cfg = cfg,
		.fanfd = fanfd,
	};

	log_info("fanotifyd started (pid=%d) -- %zu mark(s), canaries=%zu, burst=%u/%ums",
	         (int)getpid(), cfg->n_marks, cfg->n_canaries,
	         cfg->burst_threshold, cfg->burst_window_ms);

	int running = 1;
	while (running) {
		struct epoll_event events[8];
		int n = epoll_wait(ep, events, 8, -1);
		if (n < 0) {
			if (errno == EINTR) continue;
			log_err("epoll_wait: %s", strerror(errno));
			break;
		}
		for (int i = 0; i < n; i++) {
			int fd = events[i].data.fd;
			if (fd == fanfd) {
				if (fan_drain(fanfd, &mdb, on_event, &c) < 0)
					log_warn("fan_drain: %s", strerror(errno));
			} else if (fd == sigfd) {
				struct signalfd_siginfo si;
				while (read(sigfd, &si, sizeof si) == sizeof si) {
					switch (si.ssi_signo) {
					case SIGINT:
					case SIGTERM:
						log_info("received signal %u, shutting down",
						         si.ssi_signo);
						running = 0;
						break;
					case SIGHUP:
						log_info("SIGHUP received (config reload not yet implemented)");
						break;
					case SIGCHLD: {
						int status;
						while (waitpid(-1, &status, WNOHANG) > 0)
							;
						break;
					}
					default:
						break;
					}
				}
			} else if (fd == tickfd) {
				uint64_t exp;
				while (read(tickfd, &exp, sizeof exp) == sizeof exp) ;
				policy_tick(policy, monotonic_ms());
			} else if (fd == out_listen_fd(&out)) {
				out_accept(&out);
			}
		}
	}

	log_info("processed %llu events (overflow=%llu)",
	         (unsigned long long)c.stats_events,
	         (unsigned long long)c.stats_overflow);

	close(ep);
	close(tickfd);
	close(sigfd);
	if (fan_clear_marks(fanfd) < 0)
		log_warn("fanotify mark cleanup failed: %s", strerror(errno));
	close(fanfd);
	mount_db_free(&mdb);
	policy_free(policy);
	out_free(&out);
	if (cfg->pid_file && *cfg->pid_file)
		unlink(cfg->pid_file);
	return 0;
}
