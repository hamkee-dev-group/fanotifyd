#include "policy.h"
#include "fan.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <linux/fanotify.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/wait.h>
#include <unistd.h>

#define MUT_MASK (FAN_MODIFY | FAN_CLOSE_WRITE | FAN_DELETE | FAN_DELETE_SELF | \
                  FAN_MOVED_FROM | FAN_MOVED_TO | FAN_CREATE | FAN_ATTRIB)
#define CANARY_MASK (FAN_OPEN | FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM |           \
                     FAN_MODIFY | FAN_CLOSE_WRITE | FAN_MOVED_FROM |           \
                     FAN_MOVED_TO | FAN_DELETE | FAN_DELETE_SELF |             \
                     FAN_MOVE_SELF                                             \
                     )
#ifdef FAN_RENAME
#undef CANARY_MASK
#define CANARY_MASK (FAN_OPEN | FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM |            \
                     FAN_MODIFY | FAN_CLOSE_WRITE | FAN_MOVED_FROM |            \
                     FAN_MOVED_TO | FAN_DELETE | FAN_DELETE_SELF |              \
                     FAN_MOVE_SELF | FAN_RENAME)
#endif

struct pid_window {
	pid_t    pid;
	uint64_t first_ms;
	uint64_t last_ms;
	uint64_t last_alert_ms;
	uint32_t count;
};

struct policy_state {
	struct policy_cfg  cfg;      
	struct out_sink   *out;

	struct pid_window *wins;
	size_t             n_wins;
	size_t             cap_wins;
};

static char **dup_strv(char *const *v, size_t n)
{
	if (!n)
		return NULL;
	char **out = calloc(n, sizeof *out);
	if (!out)
		return NULL;
	for (size_t i = 0; i < n; i++) {
		out[i] = strdup(v[i]);
		if (!out[i]) {
			for (size_t j = 0; j < i; j++)
				free(out[j]);
			free(out);
			return NULL;
		}
	}
	return out;
}

struct policy_state *policy_new(const struct policy_cfg *cfg, struct out_sink *out)
{
	struct policy_state *p = calloc(1, sizeof *p);
	if (!p)
		return NULL;
	p->out = out;
	p->cfg.canaries = dup_strv(cfg->canaries, cfg->n_canaries);
	p->cfg.n_canaries = cfg->n_canaries;
	p->cfg.burst_threshold = cfg->burst_threshold;
	p->cfg.burst_window_ms = cfg->burst_window_ms ? cfg->burst_window_ms : 1000;
	p->cfg.hook_cmd = cfg->hook_cmd ? strdup(cfg->hook_cmd) : NULL;
	p->cfg.hook_cooldown_ms = cfg->hook_cooldown_ms ? cfg->hook_cooldown_ms : 5000;
	p->cfg.deny_on_alert = cfg->deny_on_alert;
	return p;
}

void policy_free(struct policy_state *p)
{
	if (!p)
		return;
	for (size_t i = 0; i < p->cfg.n_canaries; i++)
		free(p->cfg.canaries[i]);
	free(p->cfg.canaries);
	free(p->cfg.hook_cmd);
	free(p->wins);
	free(p);
}

static int canary_match(const struct policy_state *p, const char *path)
{
	if (!path || !*path)
		return 0;
	for (size_t i = 0; i < p->cfg.n_canaries; i++) {
		const char *pat = p->cfg.canaries[i];
		if (!pat)
			continue;
		if (fnmatch(pat, path, FNM_PATHNAME) == 0)
			return 1;
		 
		if (strchr(pat, '*') == NULL && strchr(pat, '?') == NULL &&
		    strcmp(pat, path) == 0)
			return 1;
	}
	return 0;
}

static struct pid_window *win_get(struct policy_state *p, pid_t pid)
{
	for (size_t i = 0; i < p->n_wins; i++)
		if (p->wins[i].pid == pid)
			return &p->wins[i];
	if (p->n_wins == p->cap_wins) {
		size_t cap = p->cap_wins ? p->cap_wins * 2 : 32;
		struct pid_window *w = realloc(p->wins, cap * sizeof *w);
		if (!w)
			return NULL;
		p->wins = w;
		p->cap_wins = cap;
	}
	struct pid_window *w = &p->wins[p->n_wins++];
	memset(w, 0, sizeof *w);
	w->pid = pid;
	return w;
}

static void run_hook(const char *cmd, const char *kind, pid_t pid,
                     const char *comm, const char *exe, const char *path,
                     const char *reason)
{
	if (!cmd || !*cmd)
		return;
	pid_t cpid = fork();
	if (cpid < 0) {
		log_warn("hook fork failed: %s", strerror(errno));
		return;
	}
	if (cpid == 0) {
		 
		setenv("FAN_KIND", kind ? kind : "", 1);
		char buf[32];
		snprintf(buf, sizeof buf, "%d", (int)pid);
		setenv("FAN_PID", buf, 1);
		setenv("FAN_COMM", comm ? comm : "", 1);
		setenv("FAN_EXE", exe ? exe : "", 1);
		setenv("FAN_PATH", path ? path : "", 1);
		setenv("FAN_REASON", reason ? reason : "", 1);
		 
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, 0);
			dup2(devnull, 1);
			if (devnull > 2)
				close(devnull);
		}
		execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
		_exit(127);
	}
	 
}

static const char *canary_reason(uint64_t mask)
{
	if (mask & (FAN_DELETE | FAN_DELETE_SELF))
		return "canary deleted";
#ifdef FAN_RENAME
	if (mask & FAN_RENAME)
		return "canary renamed";
#endif
	if (mask & (FAN_MOVED_FROM | FAN_MOVED_TO | FAN_MOVE_SELF))
		return "canary renamed";
	if (mask & (FAN_MODIFY | FAN_CLOSE_WRITE))
		return "canary modified";
	if (mask & (FAN_OPEN | FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM))
		return "canary opened";
	return NULL;
}

uint32_t policy_on_event(struct policy_state *p, const struct policy_input *in)
{
	if (!p || !in)
		return FAN_ALLOW;
	int mutating = (in->mask & MUT_MASK) ? 1 : 0;
	int alert = 0;
	const char *reason = NULL;

	if ((in->mask & CANARY_MASK) && canary_match(p, in->path) &&
	    (reason = canary_reason(in->mask)) != NULL) {
		struct pid_window *w = win_get(p, in->pid);
		if (w) {
			if (w->last_alert_ms == 0 ||
			    in->ts_ms - w->last_alert_ms >= p->cfg.hook_cooldown_ms) {
				out_emit_alert_line(p->out, realtime_ms(), "canary",
				                    in->pid, in->comm, in->exe, in->path,
				                    reason, NULL);
				run_hook(p->cfg.hook_cmd, "canary", in->pid, in->comm, in->exe,
				         in->path, reason);
				w->last_alert_ms = in->ts_ms;
				alert = 1;
			}
			w->last_ms = in->ts_ms;
		}
	}

	int can_deny = fan_is_perm_event(in->mask) && p->cfg.deny_on_alert;

	if (p->cfg.burst_threshold == 0 || !mutating)
		return alert && can_deny ? FAN_DENY : FAN_ALLOW;

	struct pid_window *w = win_get(p, in->pid);
	if (!w)
		return alert && can_deny ? FAN_DENY : FAN_ALLOW;
	uint64_t now = in->ts_ms;
	if (w->count == 0 || now - w->first_ms > p->cfg.burst_window_ms) {
		w->first_ms = now;
		w->count = 1;
	} else {
		w->count++;
	}
	w->last_ms = now;

	if (w->count >= p->cfg.burst_threshold) {
		if (w->last_alert_ms == 0 ||
		    now - w->last_alert_ms >= p->cfg.hook_cooldown_ms) {
			char extra[128];
			snprintf(extra, sizeof extra,
			         "\"count\":%u,\"window_ms\":%u",
			         (unsigned)w->count,
			         (unsigned)p->cfg.burst_window_ms);
			out_emit_alert_line(p->out, realtime_ms(), "burst",
			                    in->pid, in->comm, in->exe, in->path,
			                    "mutating-event burst exceeded threshold",
			                    extra);
			run_hook(p->cfg.hook_cmd, "burst", in->pid, in->comm,
			         in->exe, in->path,
			         "mutating-event burst exceeded threshold");
			alert = 1;
			w->last_alert_ms = now;
			 
			w->count = 0;
			w->first_ms = now;
		}
	}
	return alert && can_deny ? FAN_DENY : FAN_ALLOW;
}

void policy_tick(struct policy_state *p, uint64_t now_ms)
{
	if (!p)
		return;
	 
	const uint64_t IDLE = 60ull * 1000ull;
	for (size_t i = 0; i < p->n_wins; ) {
		if (now_ms - p->wins[i].last_ms > IDLE) {
			p->wins[i] = p->wins[--p->n_wins];
		} else {
			i++;
		}
	}
	 
	int status;
	while (waitpid(-1, &status, WNOHANG) > 0)
		;
}

size_t policy_window_count(const struct policy_state *p)
{
	return p ? p->n_wins : 0;
}
