#include "output.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

void out_init(struct out_sink *o)
{
	o->file_fd = -1;
	o->listen_fd = -1;
	o->sub_fds = NULL;
	o->sub_len = o->sub_cap = 0;
	o->socket_path = NULL;
	buf_init(&o->scratch);
}

static void close_subs(struct out_sink *o)
{
	for (size_t i = 0; i < o->sub_len; i++)
		if (o->sub_fds[i] >= 0)
			close(o->sub_fds[i]);
	o->sub_len = 0;
}

void out_free(struct out_sink *o)
{
	close_subs(o);
	free(o->sub_fds);
	o->sub_fds = NULL;
	o->sub_cap = 0;

	if (o->file_fd >= 0 && o->file_fd != 1 && o->file_fd != 2)
		close(o->file_fd);
	o->file_fd = -1;

	if (o->listen_fd >= 0)
		close(o->listen_fd);
	o->listen_fd = -1;

	if (o->socket_path) {
		unlink(o->socket_path);
		free(o->socket_path);
		o->socket_path = NULL;
	}

	buf_free(&o->scratch);
}

int out_open_file(struct out_sink *o, const char *path)
{
	if (!path || !*path || strcmp(path, "-") == 0) {
		o->file_fd = 1;
		return 0;
	}
	int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
	if (fd < 0)
		return -1;
	o->file_fd = fd;
	return 0;
}

int out_open_socket(struct out_sink *o, const char *path)
{
	struct sockaddr_un addr;
	if (!path || !*path)
		return -1;
	if (strlen(path) >= sizeof addr.sun_path) {
		errno = ENAMETOOLONG;
		return -1;
	}
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);

	unlink(path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		int e = errno;
		close(fd);
		errno = e;
		return -1;
	}
	if (chmod(path, 0660) < 0) {
		 
	}
	if (listen(fd, 16) < 0) {
		int e = errno;
		close(fd);
		unlink(path);
		errno = e;
		return -1;
	}
	o->listen_fd = fd;
	o->socket_path = strdup(path);
	return 0;
}

static int sub_push(struct out_sink *o, int fd)
{
	if (o->sub_len == o->sub_cap) {
		size_t cap = o->sub_cap ? o->sub_cap * 2 : 8;
		int *p = realloc(o->sub_fds, cap * sizeof *p);
		if (!p)
			return -1;
		o->sub_fds = p;
		o->sub_cap = cap;
	}
	o->sub_fds[o->sub_len++] = fd;
	return 0;
}

static void sub_drop(struct out_sink *o, size_t idx)
{
	if (idx >= o->sub_len)
		return;
	close(o->sub_fds[idx]);
	o->sub_fds[idx] = o->sub_fds[--o->sub_len];
}

int out_accept(struct out_sink *o)
{
	if (o->listen_fd < 0)
		return 0;
	for (;;) {
		int fd = accept4(o->listen_fd, NULL, NULL,
		                 SOCK_CLOEXEC | SOCK_NONBLOCK);
		if (fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (o->sub_len >= OUT_MAX_SUBSCRIBERS) {
			close(fd);
			log_warn("refusing subscriber: cap %d reached",
			         OUT_MAX_SUBSCRIBERS);
			continue;
		}
		if (sub_push(o, fd) < 0) {
			close(fd);
			return -1;
		}
		log_debug("subscriber connected fd=%d (%zu total)", fd, o->sub_len);
	}
}

static int write_all(int fd, const char *p, size_t n)
{
	while (n > 0) {
		ssize_t w = write(fd, p, n);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (w == 0)
			return -1;
		p += w;
		n -= (size_t)w;
	}
	return 0;
}

int out_emit_line(struct out_sink *o, const char *line, size_t len)
{
	if (o->file_fd >= 0) {
		if (write_all(o->file_fd, line, len) < 0 ||
		    write_all(o->file_fd, "\n", 1) < 0) {
			log_warn("write to output file failed: %s", strerror(errno));
		}
	}

	for (size_t i = 0; i < o->sub_len; ) {
		int fd = o->sub_fds[i];
		ssize_t w1 = send(fd, line, len, MSG_NOSIGNAL);
		if (w1 < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {

			log_debug("dropping slow subscriber fd=%d", fd);
			sub_drop(o, i);
			continue;
		}
		if (w1 < 0 || (size_t)w1 != len) {
			sub_drop(o, i);
			continue;
		}
		ssize_t w2 = send(fd, "\n", 1, MSG_NOSIGNAL);
		if (w2 != 1) {
			sub_drop(o, i);
			continue;
		}
		i++;
	}
	return 0;
}

int out_emit_event_line(struct out_sink *o,
                        uint64_t ts_ms, uint64_t mask,
                        const char *mask_str,
                        pid_t pid, const char *comm,
                        const char *exe, const char *path,
                        const char *name, int is_dir,
                        const char *job_id, const char *path_role,
                        const char *decision)
{
	struct buf *b = &o->scratch;
	buf_reset(b);
	if (buf_appendz(b, "{\"schema_version\":") < 0) return -1;
	buf_appendf(b, "%d", FAN_EVENT_SCHEMA_VERSION);
	buf_appendz(b, ",\"type\":\"event\",\"ts_ms\":");
	buf_appendf(b, "%llu", (unsigned long long)ts_ms);
	buf_appendz(b, ",\"mask\":");
	buf_appendf(b, "%llu", (unsigned long long)mask);
	buf_appendz(b, ",\"events\":");
	buf_append_json_string(b, mask_str ? mask_str : "");
	buf_appendz(b, ",\"decision\":");
	buf_append_json_string(b, (decision && *decision) ? decision : "observe");
	buf_appendz(b, ",\"job_id\":");
	if (job_id && *job_id)
		buf_append_json_string(b, job_id);
	else
		buf_appendz(b, "null");
	buf_appendz(b, ",\"path_role\":");
	if (path_role && *path_role)
		buf_append_json_string(b, path_role);
	else
		buf_appendz(b, "null");
	buf_appendz(b, ",\"pid\":");
	buf_appendf(b, "%d", (int)pid);
	if (comm && *comm) {
		buf_appendz(b, ",\"comm\":");
		buf_append_json_string(b, comm);
	}
	if (exe && *exe) {
		buf_appendz(b, ",\"exe\":");
		buf_append_json_string(b, exe);
	}
	buf_appendz(b, ",\"path\":");
	buf_append_json_string(b, path ? path : "");
	if (name && *name) {
		buf_appendz(b, ",\"name\":");
		buf_append_json_string(b, name);
	}
	buf_appendz(b, is_dir ? ",\"is_dir\":true" : ",\"is_dir\":false");
	if (buf_appendc(b, '}') < 0)
		return -1;
	return out_emit_line(o, b->data, b->len);
}

int out_emit_alert_line(struct out_sink *o,
                        uint64_t ts_ms, const char *kind,
                        pid_t pid, const char *comm,
                        const char *exe, const char *path,
                        const char *reason, const char *extra_kv)
{
	struct buf *b = &o->scratch;
	buf_reset(b);
	if (buf_appendz(b, "{\"type\":\"alert\",\"ts_ms\":") < 0) return -1;
	buf_appendf(b, "%llu", (unsigned long long)ts_ms);
	buf_appendz(b, ",\"kind\":");
	buf_append_json_string(b, kind ? kind : "");
	buf_appendz(b, ",\"pid\":");
	buf_appendf(b, "%d", (int)pid);
	if (comm && *comm) {
		buf_appendz(b, ",\"comm\":");
		buf_append_json_string(b, comm);
	}
	if (exe && *exe) {
		buf_appendz(b, ",\"exe\":");
		buf_append_json_string(b, exe);
	}
	if (path && *path) {
		buf_appendz(b, ",\"path\":");
		buf_append_json_string(b, path);
	}
	if (reason && *reason) {
		buf_appendz(b, ",\"reason\":");
		buf_append_json_string(b, reason);
	}
	if (extra_kv && *extra_kv) {
		buf_appendc(b, ',');
		buf_appendz(b, extra_kv);
	}
	buf_appendc(b, '}');
	return out_emit_line(o, b->data, b->len);
}
