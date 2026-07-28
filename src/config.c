#include "config.h"
#include "log.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef FANOTIFYD_TESTING
static int fail_next_mark_add;
static int fail_next_canary_add;

void daemon_cfg_test_fail_next_mark_add(void)
{
	fail_next_mark_add = 1;
}

void daemon_cfg_test_fail_next_canary_add(void)
{
	fail_next_canary_add = 1;
}
#endif

void daemon_cfg_init(struct daemon_cfg *c)
{
	memset(c, 0, sizeof *c);
	c->burst_threshold = 0;
	c->burst_window_ms = 1000;
	c->hook_cooldown_ms = 5000;
	c->want_fid = 1;
}

void daemon_cfg_free(struct daemon_cfg *c)
{
	for (size_t i = 0; i < c->n_marks; i++)
		free(c->marks[i].path);
	free(c->marks);
	for (size_t i = 0; i < c->n_canaries; i++)
		free(c->canaries[i]);
	free(c->canaries);
	free(c->out_path);
	free(c->socket_path);
	free(c->hook_cmd);
	free(c->pid_file);
	for (size_t i = 0; i < c->n_jobs; i++) {
		free(c->jobs[i].job_id);
		free(c->jobs[i].rootfs);
		free(c->jobs[i].workspace);
		free(c->jobs[i].exportdir);
		free(c->jobs[i].cachedir);
	}
	free(c->jobs);
	memset(c, 0, sizeof *c);
}

int daemon_cfg_add_mark(struct daemon_cfg *c, const char *path,
                        enum mark_type t, uint64_t mask)
{
#ifdef FANOTIFYD_TESTING
	if (fail_next_mark_add) {
		fail_next_mark_add = 0;
		return -1;
	}
#endif
	struct mark_spec *p = realloc(c->marks, (c->n_marks + 1) * sizeof *p);
	if (!p)
		return -1;
	c->marks = p;
	struct mark_spec *m = &c->marks[c->n_marks];
	memset(m, 0, sizeof *m);
	m->path = strdup(path);
	if (!m->path)
		return -1;
	m->type = t;
	m->mask = mask;
	m->children = 1;
	c->n_marks++;
	return 0;
}

int daemon_cfg_add_canary(struct daemon_cfg *c, const char *pat)
{
#ifdef FANOTIFYD_TESTING
	if (fail_next_canary_add) {
		fail_next_canary_add = 0;
		return -1;
	}
#endif
	char **p = realloc(c->canaries, (c->n_canaries + 1) * sizeof *p);
	if (!p)
		return -1;
	c->canaries = p;
	c->canaries[c->n_canaries] = strdup(pat);
	if (!c->canaries[c->n_canaries])
		return -1;
	c->n_canaries++;
	return 0;
}

static char *normalize_path(const char *path)
{
	char *p = abs_path(path);
	if (!p)
		return NULL;
	rstrip_slash(p);
	return p;
}

struct job_entry *daemon_cfg_add_job(struct daemon_cfg *c, const char *job_id)
{
	if (!job_id || !*job_id)
		return NULL;
	for (size_t i = 0; i < c->n_jobs; i++) {
		if (strcmp(c->jobs[i].job_id, job_id) == 0)
			return &c->jobs[i];
	}

	struct job_entry *jobs = realloc(c->jobs, (c->n_jobs + 1) * sizeof *jobs);
	if (!jobs)
		return NULL;
	c->jobs = jobs;
	struct job_entry *job = &c->jobs[c->n_jobs];
	memset(job, 0, sizeof *job);
	job->job_id = strdup(job_id);
	if (!job->job_id)
		return NULL;
	c->n_jobs++;
	return job;
}

int daemon_cfg_set_job_path(struct daemon_cfg *c, const char *job_id,
                            const char *role, const char *path)
{
	struct job_entry *job = daemon_cfg_add_job(c, job_id);
	if (!job || !role || !path || !*path)
		return -1;

	char *normalized = normalize_path(path);
	if (!normalized)
		return -1;

	char **slot = NULL;
	if (strcmp(role, "rootfs") == 0) {
		slot = &job->rootfs;
	} else if (strcmp(role, "workspace") == 0) {
		slot = &job->workspace;
	} else if (strcmp(role, "export") == 0) {
		slot = &job->exportdir;
	} else if (strcmp(role, "cache") == 0) {
		slot = &job->cachedir;
	} else {
		free(normalized);
		errno = EINVAL;
		return -1;
	}

	free(*slot);
	*slot = normalized;
	return 0;
}

static int parse_u32_strict(const char *s, uint32_t *out)
{
	if (!s || !*s)
		return -1;
	if (!isdigit((unsigned char)*s))
		return -1;
	errno = 0;
	char *end = NULL;
	unsigned long v = strtoul(s, &end, 10);
	if (errno == ERANGE)
		return -1;
	if (!end || *end != '\0')
		return -1;
	if (v > UINT32_MAX)
		return -1;
	*out = (uint32_t)v;
	return 0;
}

static int parse_bool_strict(const char *s, int *out)
{
	if (!s)
		return -1;
	if (strcmp(s, "1") == 0) {
		*out = 1;
		return 0;
	}
	if (strcmp(s, "0") == 0) {
		*out = 0;
		return 0;
	}
	return -1;
}

static char *trim(char *s)
{
	while (*s && isspace((unsigned char)*s))
		s++;
	if (!*s)
		return s;
	char *e = s + strlen(s) - 1;
	while (e > s && isspace((unsigned char)*e))
		*e-- = '\0';
	return s;
}

static int split_job_value(char *val, char **job_id, char **path)
{
	char *sp = val;
	while (*sp && !isspace((unsigned char)*sp))
		sp++;
	if (!*sp)
		return -1;
	*sp++ = '\0';
	*job_id = trim(val);
	*path = trim(sp);
	return (**job_id && **path) ? 0 : -1;
}

int daemon_cfg_load_file(struct daemon_cfg *c, const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	char *line = NULL;
	size_t cap = 0;
	int rc = 0;
	int lineno = 0;
	struct job_entry *current_job = NULL;
	while (getline(&line, &cap, f) != -1) {
		lineno++;
		char *s = trim(line);
		if (!*s || *s == '#')
			continue;
		 
		char *sp = s;
		while (*sp && !isspace((unsigned char)*sp))
			sp++;
		if (!*sp) {
			fprintf(stderr, "config:%d: missing value\n", lineno);
			rc = -1;
			break;
		}
		*sp++ = '\0';
		char *val = trim(sp);
		const char *key = s;

		if (strcmp(key, "watch") == 0) {
			char *p = normalize_path(val);
			if (!p) { rc = -1; break; }
			if (daemon_cfg_add_mark(c, p, MARK_INODE, 0) < 0) { free(p); rc = -1; break; }
			free(p);
		} else if (strcmp(key, "mount") == 0) {
			char *p = normalize_path(val);
			if (!p) { rc = -1; break; }
			if (daemon_cfg_add_mark(c, p, MARK_MOUNT, 0) < 0) { free(p); rc = -1; break; }
			free(p);
		} else if (strcmp(key, "filesystem") == 0) {
			char *p = normalize_path(val);
			if (!p) { rc = -1; break; }
			if (daemon_cfg_add_mark(c, p, MARK_FILESYSTEM, 0) < 0) { free(p); rc = -1; break; }
			free(p);
		} else if (strcmp(key, "canary") == 0) {
			char *p = normalize_path(val);
			const char *use = p ? p : val;
			if (daemon_cfg_add_canary(c, use) < 0) { free(p); rc = -1; break; }
			free(p);
		} else if (strcmp(key, "job") == 0) {
			current_job = daemon_cfg_add_job(c, val);
			if (!current_job) { rc = -1; break; }
		} else if (strcmp(key, "rootfs") == 0 || strcmp(key, "workspace") == 0 ||
		           strcmp(key, "export") == 0 || strcmp(key, "cache") == 0) {
			if (!current_job || !current_job->job_id) {
				fprintf(stderr, "config:%d: %s requires a preceding job\n",
				        lineno, key);
				rc = -1;
				break;
			}
			if (daemon_cfg_set_job_path(c, current_job->job_id, key, val) < 0) {
				rc = -1;
				break;
			}
		} else if (strcmp(key, "job_rootfs") == 0 ||
		           strcmp(key, "job_workspace") == 0 ||
		           strcmp(key, "job_export") == 0 ||
		           strcmp(key, "job_cache") == 0) {
			char *job_id = NULL;
			char *job_path = NULL;
			if (split_job_value(val, &job_id, &job_path) < 0) {
				fprintf(stderr, "config:%d: malformed %s entry\n", lineno, key);
				rc = -1;
				break;
			}
			const char *role = NULL;
			if (strcmp(key, "job_rootfs") == 0)
				role = "rootfs";
			else if (strcmp(key, "job_workspace") == 0)
				role = "workspace";
			else if (strcmp(key, "job_export") == 0)
				role = "export";
			else
				role = "cache";
			if (daemon_cfg_set_job_path(c, job_id, role, job_path) < 0) {
				rc = -1;
				break;
			}
		} else if (strcmp(key, "output") == 0 || strcmp(key, "out") == 0) {
			free(c->out_path);
			c->out_path = strdup(val);
		} else if (strcmp(key, "socket") == 0) {
			free(c->socket_path);
			c->socket_path = strdup(val);
		} else if (strcmp(key, "hook") == 0) {
			free(c->hook_cmd);
			c->hook_cmd = strdup(val);
		} else if (strcmp(key, "pid_file") == 0 || strcmp(key, "pidfile") == 0) {
			free(c->pid_file);
			c->pid_file = strdup(val);
		} else if (strcmp(key, "burst_threshold") == 0) {
			if (parse_u32_strict(val, &c->burst_threshold) < 0) {
				fprintf(stderr, "config:%d: invalid %s value '%s'\n",
				        lineno, key, val);
				rc = -1;
				break;
			}
		} else if (strcmp(key, "burst_window_ms") == 0) {
			if (parse_u32_strict(val, &c->burst_window_ms) < 0) {
				fprintf(stderr, "config:%d: invalid %s value '%s'\n",
				        lineno, key, val);
				rc = -1;
				break;
			}
		} else if (strcmp(key, "hook_cooldown_ms") == 0) {
			if (parse_u32_strict(val, &c->hook_cooldown_ms) < 0) {
				fprintf(stderr, "config:%d: invalid %s value '%s'\n",
				        lineno, key, val);
				rc = -1;
				break;
			}
		} else if (strcmp(key, "foreground") == 0) {
			if (parse_bool_strict(val, &c->foreground) < 0) {
				fprintf(stderr, "config:%d: invalid %s value '%s'\n",
				        lineno, key, val);
				rc = -1;
				break;
			}
		} else if (strcmp(key, "perm") == 0) {
			if (parse_bool_strict(val, &c->want_perm) < 0) {
				fprintf(stderr, "config:%d: invalid %s value '%s'\n",
				        lineno, key, val);
				rc = -1;
				break;
			}
		} else if (strcmp(key, "deny_on_alert") == 0) {
			if (parse_bool_strict(val, &c->deny_on_alert) < 0) {
				fprintf(stderr, "config:%d: invalid %s value '%s'\n",
				        lineno, key, val);
				rc = -1;
				break;
			}
		} else if (strcmp(key, "fid") == 0) {
			if (parse_bool_strict(val, &c->want_fid) < 0) {
				fprintf(stderr, "config:%d: invalid %s value '%s'\n",
				        lineno, key, val);
				rc = -1;
				break;
			}
		} else {
			fprintf(stderr, "config:%d: unknown key '%s'\n", lineno, key);
			rc = -1;
			break;
		}
	}
	free(line);
	fclose(f);
	return rc;
}

void daemon_cfg_print_usage(const char *prog)
{
	fprintf(stderr,
"Usage: %s [OPTIONS]\n"
"\n"
"  -c, --config FILE        load config from FILE\n"
"  -w, --watch PATH         watch directory inode (default: with children)\n"
"      --mount PATH         mark whole mount\n"
"      --filesystem PATH    mark whole filesystem\n"
"      --canary PATTERN     register canary path (glob OK; repeatable)\n"
"  -o, --output PATH        write JSONL events to PATH ('-' = stdout, default)\n"
"      --socket PATH        unix socket for streaming subscribers\n"
"      --hook CMD           shell command to run on alert\n"
"      --pid-file PATH      write pid to PATH on start\n"
"      --burst-threshold N  alert if pid produces >=N mutating events / window\n"
"      --burst-window-ms MS sliding window (default 1000)\n"
"      --hook-cooldown-ms MS  per-pid alert cooldown (default 5000)\n"
"      job JOBID             begin a job registry block in config files\n"
"      rootfs/workspace/export/cache PATH\n"
"                            set paths for the current config job block\n"
"  -f, --foreground         do not daemonize\n"
"      --perm               request permission events (FAN_CLASS_CONTENT)\n"
"      --deny-on-alert      deny permission events that trigger an alert\n"
"      --no-fid             use FD-mode (legacy) instead of FID-mode\n"
"  -v, --verbose            increase log verbosity (repeatable)\n"
"  -h, --help               show this help\n"
"      --version            show version\n"
"\n"
"Config file syntax: 'key value' per line. Keys: watch, mount, filesystem,\n"
"canary, output, socket, hook, pid_file, burst_threshold, burst_window_ms,\n"
"hook_cooldown_ms, foreground, perm, deny_on_alert, fid, job,\n"
"rootfs, workspace, export, cache, job_rootfs, job_workspace, job_export,\n"
"job_cache.\n"
"Boolean keys (foreground, perm, deny_on_alert, fid) accept only 0 or 1.\n",
prog);
}

int daemon_cfg_parse_argv(struct daemon_cfg *c, int argc, char **argv)
{
	enum {
		OPT_MOUNT = 1000,
		OPT_FS,
		OPT_CANARY,
		OPT_SOCKET,
		OPT_HOOK,
		OPT_PIDFILE,
		OPT_BURST_T,
		OPT_BURST_W,
		OPT_COOLDOWN,
		OPT_PERM,
		OPT_DENY_ON_ALERT,
		OPT_NOFID,
		OPT_VERSION,
	};
	static struct option longopts[] = {
		{ "config",       required_argument, NULL, 'c' },
		{ "watch",        required_argument, NULL, 'w' },
		{ "mount",        required_argument, NULL, OPT_MOUNT },
		{ "filesystem",   required_argument, NULL, OPT_FS },
		{ "canary",       required_argument, NULL, OPT_CANARY },
		{ "output",       required_argument, NULL, 'o' },
		{ "socket",       required_argument, NULL, OPT_SOCKET },
		{ "hook",         required_argument, NULL, OPT_HOOK },
		{ "pid-file",     required_argument, NULL, OPT_PIDFILE },
		{ "burst-threshold",  required_argument, NULL, OPT_BURST_T },
		{ "burst-window-ms",  required_argument, NULL, OPT_BURST_W },
		{ "hook-cooldown-ms", required_argument, NULL, OPT_COOLDOWN },
		{ "foreground",   no_argument,       NULL, 'f' },
		{ "perm",         no_argument,       NULL, OPT_PERM },
		{ "deny-on-alert", no_argument,      NULL, OPT_DENY_ON_ALERT },
		{ "no-fid",       no_argument,       NULL, OPT_NOFID },
		{ "verbose",      no_argument,       NULL, 'v' },
		{ "help",         no_argument,       NULL, 'h' },
		{ "version",      no_argument,       NULL, OPT_VERSION },
		{ 0, 0, 0, 0 },
	};

	int ch;
	const char *prog = argv[0];
	while ((ch = getopt_long(argc, argv, "c:w:o:fvh", longopts, NULL)) != -1) {
		switch (ch) {
		case 'c':
			if (daemon_cfg_load_file(c, optarg) < 0) {
				fprintf(stderr, "%s: failed to load config '%s': %s\n",
				        prog, optarg, strerror(errno));
				return -1;
			}
			break;
		case 'w': {
			char *p = abs_path(optarg);
			if (!p) {
				fprintf(stderr, "%s: bad path '%s'\n", prog, optarg);
				return -1;
			}
			rstrip_slash(p);
			int rc = daemon_cfg_add_mark(c, p, MARK_INODE, 0);
			free(p);
			if (rc < 0)
				return -1;
			break;
		}
		case OPT_MOUNT: {
			char *p = abs_path(optarg);
			if (!p) return -1;
			rstrip_slash(p);
			int rc = daemon_cfg_add_mark(c, p, MARK_MOUNT, 0);
			free(p);
			if (rc < 0)
				return -1;
			break;
		}
		case OPT_FS: {
			char *p = abs_path(optarg);
			if (!p) return -1;
			rstrip_slash(p);
			int rc = daemon_cfg_add_mark(c, p, MARK_FILESYSTEM, 0);
			free(p);
			if (rc < 0)
				return -1;
			break;
		}
		case OPT_CANARY: {
			char *p = abs_path(optarg);
			if (!p) {
				fprintf(stderr, "%s: bad path '%s'\n", prog, optarg);
				return -1;
			}
			int rc = daemon_cfg_add_canary(c, p);
			free(p);
			if (rc < 0)
				return -1;
			break;
		}
		case 'o':       free(c->out_path);     c->out_path = strdup(optarg); break;
		case OPT_SOCKET:free(c->socket_path);  c->socket_path = strdup(optarg); break;
		case OPT_HOOK:  free(c->hook_cmd);     c->hook_cmd = strdup(optarg); break;
		case OPT_PIDFILE: free(c->pid_file);   c->pid_file = strdup(optarg); break;
		case OPT_BURST_T:
			if (parse_u32_strict(optarg, &c->burst_threshold) < 0) {
				fprintf(stderr, "%s: invalid --burst-threshold value '%s'\n",
				        prog, optarg);
				return -1;
			}
			break;
		case OPT_BURST_W:
			if (parse_u32_strict(optarg, &c->burst_window_ms) < 0) {
				fprintf(stderr, "%s: invalid --burst-window-ms value '%s'\n",
				        prog, optarg);
				return -1;
			}
			break;
		case OPT_COOLDOWN:
			if (parse_u32_strict(optarg, &c->hook_cooldown_ms) < 0) {
				fprintf(stderr, "%s: invalid --hook-cooldown-ms value '%s'\n",
				        prog, optarg);
				return -1;
			}
			break;
		case 'f':          c->foreground = 1;   break;
		case OPT_PERM:     c->want_perm = 1;    break;
		case OPT_DENY_ON_ALERT: c->deny_on_alert = 1; break;
		case OPT_NOFID:    c->want_fid = 0;     break;
		case 'v':          c->verbose++;        break;
		case OPT_VERSION:
			printf("fanotifyd 0.1.0\n");
			exit(0);
		case 'h':
			daemon_cfg_print_usage(prog);
			exit(0);
		default:
			daemon_cfg_print_usage(prog);
			return -1;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "%s: unexpected argument '%s'\n", prog, argv[optind]);
		return -1;
	}
	return 0;
}
