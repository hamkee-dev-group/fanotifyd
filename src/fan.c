#include "fan.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fanotify.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef FAN_EVENT_INFO_TYPE_FID
#define FAN_EVENT_INFO_TYPE_FID 1
#endif

#define FAN_EVENT_BUF_LEN (4096 * 16)





int fan_fid_reporting(int want_fid, int want_perm)
{
	return want_fid && !want_perm;
}

uint64_t fan_fid_only_events(void)
{
	uint64_t m = FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO |
	             FAN_ATTRIB | FAN_MOVE_SELF | FAN_DELETE_SELF;
#ifdef FAN_RENAME
	m |= FAN_RENAME;
#endif
	return m;
}

static uint64_t default_mask(int want_fid, int want_perm)
{
	if (want_perm) {
		uint64_t m = FAN_OPEN | FAN_OPEN_PERM | FAN_ACCESS_PERM |
		             FAN_ONDIR | FAN_EVENT_ON_CHILD;
		return m;
	}

	uint64_t m = FAN_MODIFY | FAN_CLOSE_WRITE | FAN_OPEN |
	             FAN_ONDIR | FAN_EVENT_ON_CHILD;
	if (fan_fid_reporting(want_fid, want_perm))
		m |= fan_fid_only_events();
	return m;
}

uint64_t fan_compute_mark_mask(const struct mark_spec *m, int want_fid,
                               int want_perm)
{
	uint64_t mask = (m && m->mask) ? m->mask : default_mask(want_fid, want_perm);
	if (m && m->children)
		mask |= FAN_EVENT_ON_CHILD;
	return mask;
}

int fan_init(int *out_fd, int want_fid, int want_perm)
{
	unsigned int flags = FAN_CLOEXEC | FAN_NONBLOCK;
	if (fan_fid_reporting(want_fid, want_perm)) {
#ifdef FAN_REPORT_DFID_NAME
		flags |= FAN_REPORT_DFID_NAME | FAN_REPORT_FID;
#else
		flags |= FAN_REPORT_FID;
#endif
	}
	flags |= want_perm ? FAN_CLASS_CONTENT : FAN_CLASS_NOTIF;

	int fd = fanotify_init(flags, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
	if (fd < 0)
		return -1;
	*out_fd = fd;
	return 0;
}

int fan_clear_marks(int fanfd)
{
	return fanotify_mark(fanfd, FAN_MARK_FLUSH, 0, AT_FDCWD, NULL);
}

int fan_mark(int fanfd, struct mount_db *db, const struct mark_spec *m,
             int want_fid, int want_perm)
{
	unsigned int mflags = FAN_MARK_ADD;
	switch (m->type) {
	case MARK_INODE:                                     break;
	case MARK_MOUNT:       mflags |= FAN_MARK_MOUNT;     break;
	case MARK_FILESYSTEM:  mflags |= FAN_MARK_FILESYSTEM; break;
	}

	uint64_t mask = fan_compute_mark_mask(m, want_fid, want_perm);

	if (fan_fid_reporting(want_fid, want_perm) &&
	    mount_db_add_for_path(db, m->path) < 0) {
		log_warn("mount_db_add_for_path(%s) failed: %s",
		         m->path, strerror(errno));
		 
	}

	if (fanotify_mark(fanfd, mflags, mask, AT_FDCWD, m->path) < 0) {
		if (errno == EINVAL && !fan_fid_reporting(want_fid, want_perm) &&
		    (mask & fan_fid_only_events()) != 0)
			log_err("mark %s requests create/delete/move/attrib "
			        "events, which the kernel only reports with "
			        "file handles; drop them or stop disabling fid",
			        m->path);
		return -1;
	}

	return 0;
}

int fan_is_perm_event(uint64_t mask)
{
	return (mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM)) ? 1 : 0;
}

int fan_respond(int fanfd, int event_fd, uint32_t response)
{
	if (response != FAN_ALLOW && response != FAN_DENY) {
		errno = EINVAL;
		return -1;
	}

	struct fanotify_response resp = {
		.fd = event_fd,
		.response = response,
	};
	ssize_t n;

	do {
		n = write(fanfd, &resp, sizeof resp);
	} while (n < 0 && errno == EINTR);

	return n == (ssize_t)sizeof resp ? 0 : -1;
}

struct mask_name {
	uint64_t bit;
	const char *name;
};

static const struct mask_name MASK_NAMES[] = {
	{ FAN_ACCESS,        "ACCESS" },
	{ FAN_MODIFY,        "MODIFY" },
	{ FAN_ATTRIB,        "ATTRIB" },
	{ FAN_CLOSE_WRITE,   "CLOSE_WRITE" },
	{ FAN_CLOSE_NOWRITE, "CLOSE_NOWRITE" },
	{ FAN_OPEN,          "OPEN" },
	{ FAN_MOVED_FROM,    "MOVED_FROM" },
	{ FAN_MOVED_TO,      "MOVED_TO" },
	{ FAN_CREATE,        "CREATE" },
	{ FAN_DELETE,        "DELETE" },
	{ FAN_DELETE_SELF,   "DELETE_SELF" },
	{ FAN_MOVE_SELF,     "MOVE_SELF" },
	{ FAN_OPEN_EXEC,     "OPEN_EXEC" },
	{ FAN_Q_OVERFLOW,    "Q_OVERFLOW" },
#ifdef FAN_FS_ERROR
	{ FAN_FS_ERROR,      "FS_ERROR" },
#endif
	{ FAN_OPEN_PERM,     "OPEN_PERM" },
	{ FAN_ACCESS_PERM,   "ACCESS_PERM" },
	{ FAN_OPEN_EXEC_PERM,"OPEN_EXEC_PERM" },
#ifdef FAN_RENAME
	{ FAN_RENAME,        "RENAME" },
#endif
	{ FAN_ONDIR,         "ONDIR" },
};

size_t fan_mask_str(uint64_t mask, char *out, size_t cap)
{
	size_t total = 0;
	size_t pos = 0;
	uint64_t known = 0;
	int first = 1;
	int stopped = (cap == 0);

	for (size_t i = 0; i < sizeof MASK_NAMES / sizeof MASK_NAMES[0]; i++) {
		if (!(mask & MASK_NAMES[i].bit))
			continue;
		known |= MASK_NAMES[i].bit;
		const char *nm = MASK_NAMES[i].name;
		size_t l = strlen(nm);
		size_t need = (first ? 0 : 1) + l;
		total += need;
		if (!stopped) {
			if (pos + need + 1 <= cap) {
				if (!first)
					out[pos++] = ',';
				memcpy(out + pos, nm, l);
				pos += l;
			} else {
				stopped = 1;
			}
		}
		first = 0;
	}

	uint64_t unknown = mask & ~known;
	if (unknown) {
		char hex[32];
		int h = snprintf(hex, sizeof hex, "0x%" PRIx64, unknown);
		size_t need = (first ? 0 : 1) + (size_t)h;
		total += need;
		if (!stopped && pos + need + 1 <= cap) {
			if (!first)
				out[pos++] = ',';
			memcpy(out + pos, hex, (size_t)h);
			pos += (size_t)h;
		}
	}

	if (cap > 0)
		out[pos] = '\0';

	return total;
}

static int try_resolve_via_fid(struct mount_db *db,
                               const struct fanotify_event_info_fid *fid,
                               char *path_out, size_t path_cap,
                               char *name_out, size_t name_cap,
                               int has_name)
{
	int mfd = mount_db_lookup(db, &fid->fsid);
	if (mfd < 0) {
		errno = ENOENT;
		return -1;
	}
	 
	const char *p = (const char *)fid + sizeof(struct fanotify_event_info_fid);
	struct file_handle *fh = (struct file_handle *)p;
	const char *name = NULL;
	if (has_name) {
		size_t fh_size = sizeof(struct file_handle) + fh->handle_bytes;
		name = p + fh_size;
	}

	int fd = syscall(SYS_open_by_handle_at, mfd, fh, O_RDONLY | O_PATH | O_CLOEXEC);
	if (fd < 0)
		return -1;

	char dir_path[4096];
	if (resolve_fd_path(fd, dir_path, sizeof dir_path) < 0) {
		int e = errno;
		close(fd);
		errno = e;
		return -1;
	}
	close(fd);

	if (has_name && name && *name) {
		int has_slash = (dir_path[0] != '\0' &&
		                 dir_path[strlen(dir_path) - 1] == '/');
		snprintf(path_out, path_cap, "%s%s%s",
		         dir_path, has_slash ? "" : "/", name);
		if (name_out && name_cap > 0) {
			strncpy(name_out, name, name_cap - 1);
			name_out[name_cap - 1] = '\0';
		}
	} else {
		size_t dl = strnlen(dir_path, sizeof dir_path);
		size_t cp = dl < path_cap - 1 ? dl : path_cap - 1;
		memcpy(path_out, dir_path, cp);
		path_out[cp] = '\0';
		if (name_out && name_cap > 0)
			name_out[0] = '\0';
	}
	return 0;
}

static void parse_one(struct fanotify_event_metadata *meta,
                      struct mount_db *db,
                      fan_event_cb cb, void *user)
{
	struct fan_event ev;
	memset(&ev, 0, sizeof ev);
	ev.fd = -1;
	ev.mask = meta->mask;
	ev.pid = meta->pid;
	ev.is_dir = (meta->mask & FAN_ONDIR) ? 1 : 0;
	ev.requires_response = fan_is_perm_event(meta->mask);
	ev.is_perm = ev.requires_response;
	ev.from_overflow = (meta->mask & FAN_Q_OVERFLOW) ? 1 : 0;

	if (ev.from_overflow) {
		strcpy(ev.path, "<overflow>");
		cb(&ev, user);
		return;
	}

	 
	if (meta->fd >= 0) {
		ev.had_fd = 1;
		ev.fd = meta->fd;
		if (resolve_fd_path(meta->fd, ev.path, sizeof ev.path) < 0)
			snprintf(ev.path, sizeof ev.path, "<fd:%d>", meta->fd);
	}

	 
	size_t off = meta->event_len ? sizeof *meta : 0;
	if (meta->event_len > off) {
		const char *base = (const char *)meta;
		while (off + sizeof(struct fanotify_event_info_header) <= meta->event_len) {
			const struct fanotify_event_info_header *h =
				(const struct fanotify_event_info_header *)(base + off);
			if (h->len < sizeof *h || off + h->len > meta->event_len)
				break;
			switch (h->info_type) {
			case FAN_EVENT_INFO_TYPE_FID:
			case FAN_EVENT_INFO_TYPE_DFID:
			case FAN_EVENT_INFO_TYPE_DFID_NAME:
#ifdef FAN_EVENT_INFO_TYPE_OLD_DFID_NAME
			case FAN_EVENT_INFO_TYPE_OLD_DFID_NAME:
#endif
#ifdef FAN_EVENT_INFO_TYPE_NEW_DFID_NAME
			case FAN_EVENT_INFO_TYPE_NEW_DFID_NAME:
#endif
			{
				const struct fanotify_event_info_fid *fid =
					(const struct fanotify_event_info_fid *)h;
				int has_name = (h->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME);
#ifdef FAN_EVENT_INFO_TYPE_OLD_DFID_NAME
				if (h->info_type == FAN_EVENT_INFO_TYPE_OLD_DFID_NAME)
					has_name = 1;
#endif
#ifdef FAN_EVENT_INFO_TYPE_NEW_DFID_NAME
				if (h->info_type == FAN_EVENT_INFO_TYPE_NEW_DFID_NAME)
					has_name = 1;
#endif
				


				int set_path = (ev.path[0] == '\0') ||
				               (h->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME)
#ifdef FAN_EVENT_INFO_TYPE_NEW_DFID_NAME
				               || (h->info_type == FAN_EVENT_INFO_TYPE_NEW_DFID_NAME)
#endif
				               ;
				if (set_path) {
					if (try_resolve_via_fid(db, fid,
					                        ev.path, sizeof ev.path,
					                        ev.name, sizeof ev.name,
					                        has_name) < 0) {
						if (ev.path[0] == '\0')
							snprintf(ev.path, sizeof ev.path,
							         "<fid-unresolved>");
					}
				}
				break;
			}
			default:
				break;
			}
			off += h->len;
		}
	}

	if (ev.path[0] == '\0')
		strcpy(ev.path, "<unknown>");

	cb(&ev, user);

	if (ev.had_fd && ev.fd >= 0 && !ev.requires_response)
		close(ev.fd);
}

int fan_drain(int fanfd, struct mount_db *db, fan_event_cb cb, void *user)
{
	for (;;) {
		_Alignas(8) char buf[FAN_EVENT_BUF_LEN];
		ssize_t n = read(fanfd, buf, sizeof buf);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return 0;

		struct fanotify_event_metadata *meta =
			(struct fanotify_event_metadata *)buf;
		while (FAN_EVENT_OK(meta, n)) {
			if (meta->vers != FANOTIFY_METADATA_VERSION) {
				log_warn("fanotify metadata version mismatch (%u vs %u)",
				         meta->vers, FANOTIFY_METADATA_VERSION);
				return -1;
			}
			parse_one(meta, db, cb, user);
			meta = FAN_EVENT_NEXT(meta, n);
		}
	}
}
