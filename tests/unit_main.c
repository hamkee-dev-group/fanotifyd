#include "config.h"
#include "buf.h"
#include "daemon.h"
#include "fan.h"
#include "output.h"
#include "path.h"
#include "policy.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/fanotify.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		failures++; \
	} \
} while (0)

#define CHECK_CONTAINS(haystack, needle) do { \
	const char *_h = (haystack); \
	const char *_n = (needle); \
	if (!strstr(_h, _n)) { \
		fprintf(stderr, "FAIL %s:%d: missing substring \"%s\" in \"%s\"\n", \
			__FILE__, __LINE__, _n, _h); \
		failures++; \
	} \
} while (0)

#define CHECK_STREQ(got, want) do { \
	const char *_g = (got); \
	const char *_w = (want); \
	if (strcmp(_g, _w) != 0) { \
		fprintf(stderr, "FAIL %s:%d: got \"%s\" want \"%s\"\n", \
			__FILE__, __LINE__, _g, _w); \
		failures++; \
	} \
} while (0)

static void test_json_escape(void)
{
	struct buf b;
	buf_init(&b);
	const char in[] = "a\"b\\c\nd\te\x01" "f";
	CHECK(buf_append_json_string_n(&b, in, sizeof in - 1) == 0);
	CHECK_STREQ(b.data, "\"a\\\"b\\\\c\\nd\\te\\u0001f\"");
	buf_free(&b);

	buf_init(&b);
	CHECK(buf_append_json_string(&b, "plain") == 0);
	CHECK_STREQ(b.data, "\"plain\"");
	buf_free(&b);

	buf_init(&b);
	const char utf8_in[] = "\b\f\x1f\xc3\xa9";
	CHECK(buf_append_json_string_n(&b, utf8_in, sizeof utf8_in - 1) == 0);
	CHECK_STREQ(b.data, "\"\\b\\f\\u001f\xc3\xa9\"");
	buf_free(&b);
}

static void test_rstrip_slash(void)
{
	char a[] = "/";
	rstrip_slash(a);
	CHECK_STREQ(a, "/");

	char b[] = "/tmp///";
	rstrip_slash(b);
	CHECK_STREQ(b, "/tmp");

	char c[] = "/tmp";
	rstrip_slash(c);
	CHECK_STREQ(c, "/tmp");

	rstrip_slash(NULL);
}

static int write_temp_config(char path[], size_t pathsz, const char *contents)
{
	snprintf(path, pathsz, "/tmp/fanotifyd-config-XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0)
		return -1;

	FILE *f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		unlink(path);
		return -1;
	}

	if (fputs(contents, f) == EOF) {
		fclose(f);
		unlink(path);
		return -1;
	}

	if (fclose(f) != 0) {
		unlink(path);
		return -1;
	}

	return 0;
}

static int init_capture_sink(struct out_sink *out, char path[], size_t pathsz)
{
	snprintf(path, pathsz, "/tmp/fanotifyd-capture-XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0)
		return -1;
	out_init(out);
	out->file_fd = fd;
	return 0;
}

static char *slurp_fd(int fd)
{
	off_t end = lseek(fd, 0, SEEK_END);
	if (end < 0)
		return NULL;
	if (lseek(fd, 0, SEEK_SET) < 0)
		return NULL;

	size_t len = (size_t)end;
	char *buf = calloc(len + 1, 1);
	if (!buf)
		return NULL;
	size_t off = 0;
	while (off < len) {
		ssize_t n = read(fd, buf + off, len - off);
		if (n < 0) {
			free(buf);
			return NULL;
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	buf[off] = '\0';
	return buf;
}

static int count_substr(const char *s, const char *needle)
{
	int count = 0;
	size_t nlen = strlen(needle);
	const char *p = s;
	while ((p = strstr(p, needle)) != NULL) {
		count++;
		p += nlen;
	}
	return count;
}

static void test_config_load_file(void)
{
	struct daemon_cfg cfg;
	char path[] = "/tmp/fanotifyd-config-XXXXXX";
	const char *contents =
		"# comment\n"
		"\n"
		"output /tmp/events.jsonl\n"
		"socket /tmp/fanotifyd.sock\n"
		"hook /bin/sh -c true\n"
		"pid_file /tmp/fanotifyd.pid\n"
		"burst_threshold 7\n"
		"burst_window_ms 250\n"
		"hook_cooldown_ms 900\n"
		"foreground 1\n"
		"perm 1\n"
		"fid 0\n";

	if (write_temp_config(path, sizeof path, contents) < 0) {
		CHECK(0);
		return;
	}

	daemon_cfg_init(&cfg);
	CHECK(daemon_cfg_load_file(&cfg, path) == 0);
	CHECK_STREQ(cfg.out_path, "/tmp/events.jsonl");
	CHECK_STREQ(cfg.socket_path, "/tmp/fanotifyd.sock");
	CHECK_STREQ(cfg.hook_cmd, "/bin/sh -c true");
	CHECK_STREQ(cfg.pid_file, "/tmp/fanotifyd.pid");
	CHECK(cfg.burst_threshold == 7);
	CHECK(cfg.burst_window_ms == 250);
	CHECK(cfg.hook_cooldown_ms == 900);
	CHECK(cfg.foreground == 1);
	CHECK(cfg.want_perm == 1);
	CHECK(cfg.want_fid == 0);
	daemon_cfg_free(&cfg);
	CHECK(unlink(path) == 0);
}

static void test_config_load_job_registry(void)
{
	struct daemon_cfg cfg;
	char path[] = "/tmp/fanotifyd-config-XXXXXX";
	const char *contents =
		"job jobA\n"
		"rootfs /tmp/job/root/\n"
		"workspace /tmp/job/workspace/\n"
		"job_export jobA /tmp/job/export/\n"
		"job_cache jobA /tmp/job/cache/\n";

	if (write_temp_config(path, sizeof path, contents) < 0) {
		CHECK(0);
		return;
	}

	daemon_cfg_init(&cfg);
	CHECK(daemon_cfg_load_file(&cfg, path) == 0);
	CHECK(cfg.n_jobs == 1);
	CHECK_STREQ(cfg.jobs[0].job_id, "jobA");
	CHECK_STREQ(cfg.jobs[0].rootfs, "/tmp/job/root");
	CHECK_STREQ(cfg.jobs[0].workspace, "/tmp/job/workspace");
	CHECK_STREQ(cfg.jobs[0].exportdir, "/tmp/job/export");
	CHECK_STREQ(cfg.jobs[0].cachedir, "/tmp/job/cache");
	daemon_cfg_free(&cfg);
	CHECK(unlink(path) == 0);
}

static void test_config_load_job_registry_rejects_malformed_entry(void)
{
	struct daemon_cfg cfg;
	char path[] = "/tmp/fanotifyd-config-XXXXXX";

	if (write_temp_config(path, sizeof path, "job_rootfs jobA\n") < 0) {
		CHECK(0);
		return;
	}

	daemon_cfg_init(&cfg);
	CHECK(daemon_cfg_load_file(&cfg, path) == -1);
	daemon_cfg_free(&cfg);
	CHECK(unlink(path) == 0);
}

static void test_config_load_file_rejects_unknown_key(void)
{
	struct daemon_cfg cfg;
	char path[] = "/tmp/fanotifyd-config-XXXXXX";

	if (write_temp_config(path, sizeof path, "unknown_key 1\n") < 0) {
		CHECK(0);
		return;
	}

	daemon_cfg_init(&cfg);
	CHECK(daemon_cfg_load_file(&cfg, path) == -1);
	daemon_cfg_free(&cfg);
	CHECK(unlink(path) == 0);
}

static void test_config_load_file_rejects_missing_value(void)
{
	struct daemon_cfg cfg;
	char path[] = "/tmp/fanotifyd-config-XXXXXX";

	if (write_temp_config(path, sizeof path, "output\n") < 0) {
		CHECK(0);
		return;
	}

	daemon_cfg_init(&cfg);
	CHECK(daemon_cfg_load_file(&cfg, path) == -1);
	daemon_cfg_free(&cfg);
	CHECK(unlink(path) == 0);
}

static void test_job_classify_path(void)
{
	struct daemon_cfg cfg;
	const char *job_id = NULL;
	const char *path_role = NULL;

	daemon_cfg_init(&cfg);
	CHECK(daemon_cfg_set_job_path(&cfg, "J", "rootfs", "/tmp/job/root") == 0);
	CHECK(daemon_cfg_set_job_path(&cfg, "J", "workspace", "/tmp/job/root/work") == 0);
	CHECK(job_classify_path(&cfg, "/tmp/job/root", &job_id, &path_role) == 1);
	CHECK_STREQ(job_id, "J");
	CHECK_STREQ(path_role, "rootfs");
	CHECK(job_classify_path(&cfg, "/tmp/job/root/file", &job_id, &path_role) == 1);
	CHECK_STREQ(job_id, "J");
	CHECK_STREQ(path_role, "rootfs");
	CHECK(job_classify_path(&cfg, "/tmp/job/root/work/file", &job_id, &path_role) == 1);
	CHECK_STREQ(job_id, "J");
	CHECK_STREQ(path_role, "workspace");
	CHECK(job_classify_path(&cfg, "/tmp/job/root2", &job_id, &path_role) == 0);
	CHECK(job_classify_path(&cfg, "/tmp/job/root2/file", &job_id, &path_role) == 0);
	CHECK(job_classify_path(&cfg, "/tmp/job/rootish", &job_id, &path_role) == 0);
	CHECK(job_classify_path(&cfg, "/tmp/job", &job_id, &path_role) == 0);
	CHECK(job_classify_path(&cfg, NULL, &job_id, &path_role) == 0);
	CHECK(job_classify_path(&cfg, "", &job_id, &path_role) == 0);
	daemon_cfg_free(&cfg);
}

static void test_output_event_json(void)
{
	struct out_sink out;

	out_init(&out);
	CHECK(out_emit_event_line(&out,
	                          17, 9,
	                          "OPEN\"\n",
	                          321, "proc\\name",
	                          "/bin/tool",
	                          "/tmp/a\"b\\c",
	                          "line\nnext", 1,
	                          "J", "rootfs", NULL) == 0);
	CHECK_STREQ(out.scratch.data,
	            "{\"schema_version\":1,\"type\":\"event\",\"ts_ms\":17,"
	            "\"mask\":9,\"events\":\"OPEN\\\"\\n\",\"decision\":\"observe\","
	            "\"job_id\":\"J\",\"path_role\":\"rootfs\",\"pid\":321,"
	            "\"comm\":\"proc\\\\name\",\"exe\":\"/bin/tool\","
	            "\"path\":\"/tmp/a\\\"b\\\\c\",\"name\":\"line\\nnext\","
	            "\"is_dir\":true}");

	CHECK(out_emit_event_line(&out,
	                          18, 10,
	                          "ACCESS",
	                          322, NULL,
	                          NULL,
	                          "/tmp/none",
	                          NULL, 0,
	                          NULL, NULL, "allow") == 0);
	CHECK_STREQ(out.scratch.data,
	            "{\"schema_version\":1,\"type\":\"event\",\"ts_ms\":18,"
	            "\"mask\":10,\"events\":\"ACCESS\",\"decision\":\"allow\","
	            "\"job_id\":null,\"path_role\":null,\"pid\":322,"
	            "\"path\":\"/tmp/none\",\"is_dir\":false}");
	out_free(&out);
}

static void test_output_alert_overflow_with_path(void)
{
	struct out_sink out;
	out_init(&out);
	CHECK(out_emit_alert_line(&out, 42, "overflow", 0, NULL, NULL,
	                          "<overflow>", "fanotify queue overflowed",
	                          NULL) == 0);
	CHECK_CONTAINS(out.scratch.data, "\"type\":\"alert\"");
	CHECK_CONTAINS(out.scratch.data, "\"kind\":\"overflow\"");
	CHECK_CONTAINS(out.scratch.data, "\"pid\":0");
	CHECK_CONTAINS(out.scratch.data, "\"path\":\"<overflow>\"");
	CHECK_CONTAINS(out.scratch.data, "\"reason\":\"fanotify queue overflowed\"");
	out_free(&out);
}

static void test_output_alert_overflow_no_optional_fields(void)
{
	struct out_sink o;
	out_init(&o);
	CHECK(out_emit_alert_line(&o, 99, "overflow", 0, NULL, NULL, NULL,
	                          "fanotify queue overflowed", NULL) == 0);
	CHECK_STREQ(o.scratch.data,
	            "{\"type\":\"alert\",\"ts_ms\":99,\"kind\":\"overflow\","
	            "\"pid\":0,\"reason\":\"fanotify queue overflowed\"}");
	out_free(&o);
}

static void test_fan_compute_mark_mask(void)
{
	struct mark_spec mark = {
		.path = "/tmp/x",
		.type = MARK_INODE,
		.mask = 0,
		.children = 0,
	};

	uint64_t mask = fan_compute_mark_mask(&mark, 1, 0);
	CHECK((mask & FAN_OPEN_PERM) == 0);
	CHECK((mask & FAN_ACCESS_PERM) == 0);

	mask = fan_compute_mark_mask(&mark, 1, 1);
	CHECK((mask & FAN_OPEN_PERM) != 0);
	CHECK((mask & FAN_ACCESS_PERM) != 0);

	mark.mask = FAN_OPEN | FAN_DELETE;
	mask = fan_compute_mark_mask(&mark, 1, 1);
	CHECK(mask == (FAN_OPEN | FAN_DELETE));

	mark.mask = 0;
	mask = fan_compute_mark_mask(&mark, 1, 0);
	CHECK((mask & fan_fid_only_events()) == fan_fid_only_events());

	mask = fan_compute_mark_mask(&mark, 0, 0);
	CHECK((mask & fan_fid_only_events()) == 0);
	CHECK((mask & FAN_OPEN) != 0);
	CHECK((mask & FAN_MODIFY) != 0);
	CHECK((mask & FAN_CLOSE_WRITE) != 0);

	mask = fan_compute_mark_mask(&mark, 1, 1);
	CHECK((mask & fan_fid_only_events()) == 0);

	CHECK(fan_fid_reporting(1, 0) != 0);
	CHECK(fan_fid_reporting(0, 0) == 0);
	CHECK(fan_fid_reporting(1, 1) == 0);
}

static void test_fan_mask_str(void)
{
	char buf[64];

	CHECK(fan_mask_str(FAN_CREATE | FAN_ONDIR, buf, sizeof buf) == 12);
	CHECK_STREQ(buf, "CREATE,ONDIR");

	CHECK(fan_mask_str(FAN_OPEN_PERM | FAN_ACCESS_PERM, buf, sizeof buf) == 21);
	CHECK_STREQ(buf, "OPEN_PERM,ACCESS_PERM");

	CHECK(fan_mask_str(1ULL << 63, buf, sizeof buf) == 18);
	CHECK_STREQ(buf, "0x8000000000000000");

	char small[6];
	memset(small, 'x', sizeof small);
	CHECK(fan_mask_str(FAN_OPEN | FAN_ACCESS_PERM, small, sizeof small) == 16);
	CHECK_STREQ(small, "OPEN");
}

static void test_fan_mask_str_contract(void)
{
	{
		char buf[64];
		memset(buf, 'x', sizeof buf);
		CHECK(fan_mask_str(0, buf, sizeof buf) == 0);
		CHECK_STREQ(buf, "");
	}

	{
		char buf[256];
		memset(buf, 'x', sizeof buf);
		size_t ret = fan_mask_str(FAN_OPEN | FAN_MODIFY, buf, sizeof buf);
		CHECK(ret == strlen(buf));
		CHECK_CONTAINS(buf, "OPEN");
		CHECK_CONTAINS(buf, "MODIFY");
		size_t len = strlen(buf);
		CHECK(len > 0 && buf[len - 1] != ',');
		CHECK(buf[0] != ',');
		CHECK(strstr(buf, ",,") == NULL);
	}

	{
		char buf[256];
		memset(buf, 'x', sizeof buf);
		size_t ret = fan_mask_str((1ULL << 60) | FAN_OPEN, buf, sizeof buf);
		CHECK(ret == strlen(buf));
		CHECK_CONTAINS(buf, "OPEN");
		CHECK_CONTAINS(buf, "0x1000000000000000");
	}

	{
		char buf[8];
		memset(buf, 'x', sizeof buf);
		size_t ret = fan_mask_str(FAN_OPEN | FAN_MODIFY | FAN_ATTRIB,
		                          buf, sizeof buf);
		size_t len = strnlen(buf, sizeof buf);
		CHECK(len < sizeof buf);

		static const char *const known[] = {
			"ACCESS", "MODIFY", "ATTRIB",
			"CLOSE_WRITE", "CLOSE_NOWRITE",
			"OPEN", "MOVED_FROM", "MOVED_TO",
			"CREATE", "DELETE", "DELETE_SELF", "MOVE_SELF",
			"OPEN_EXEC", "Q_OVERFLOW", "FS_ERROR",
			"OPEN_PERM", "ACCESS_PERM", "OPEN_EXEC_PERM",
			"RENAME", "ONDIR",
		};
		char copy[sizeof buf];
		memcpy(copy, buf, sizeof copy);
		char *save = NULL;
		for (char *tok = strtok_r(copy, ",", &save); tok;
		     tok = strtok_r(NULL, ",", &save)) {
			int ok = 0;
			for (size_t i = 0; i < sizeof known / sizeof known[0]; i++) {
				if (strcmp(tok, known[i]) == 0) {
					ok = 1;
					break;
				}
			}
			CHECK(ok);
		}
		CHECK(ret >= len);
	}
}

static void test_policy_canary_alerts(void)
{
	struct out_sink out;
	char path[] = "/tmp/fanotifyd-capture-XXXXXX";
	char canary_pattern[] = "/tmp/canary*";
	char *canaries[] = { canary_pattern };
	struct policy_cfg cfg = {
		.canaries = canaries,
		.n_canaries = 1,
		.hook_cooldown_ms = 1,
	};

	if (init_capture_sink(&out, path, sizeof path) < 0) {
		CHECK(0);
		return;
	}

	struct policy_state *policy = policy_new(&cfg, &out);
	CHECK(policy != NULL);
	if (!policy) {
		out_free(&out);
		unlink(path);
		return;
	}

	struct policy_input in = {
		.ts_ms = 100,
		.pid = 42,
		.path = "/tmp/canary",
	};

	in.mask = FAN_ACCESS;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 101;
	in.mask = FAN_OPEN;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 102;
	in.mask = FAN_MODIFY;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 103;
	in.mask = FAN_MOVED_FROM;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 104;
	in.mask = FAN_DELETE;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 105;
	in.path = "/tmp/not-canary";
	in.mask = FAN_OPEN;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);

	char *captured = slurp_fd(out.file_fd);
	CHECK(captured != NULL);
	if (captured) {
		CHECK(count_substr(captured, "\"kind\":\"canary\"") == 4);
		CHECK_CONTAINS(captured, "\"reason\":\"canary opened\"");
		CHECK_CONTAINS(captured, "\"reason\":\"canary modified\"");
		CHECK_CONTAINS(captured, "\"reason\":\"canary renamed\"");
		CHECK_CONTAINS(captured, "\"reason\":\"canary deleted\"");
	}
	free(captured);

	policy_free(policy);
	out_free(&out);
	CHECK(unlink(path) == 0);
}

static void test_policy_burst_behavior(void)
{
	struct out_sink out;
	char path[] = "/tmp/fanotifyd-capture-XXXXXX";
	struct policy_cfg cfg = {
		.burst_threshold = 2,
		.burst_window_ms = 100,
		.hook_cooldown_ms = 500,
	};

	if (init_capture_sink(&out, path, sizeof path) < 0) {
		CHECK(0);
		return;
	}

	struct policy_state *policy = policy_new(&cfg, &out);
	CHECK(policy != NULL);
	if (!policy) {
		out_free(&out);
		unlink(path);
		return;
	}

	struct policy_input in = {
		.pid = 7,
		.path = "/tmp/data",
	};

	in.ts_ms = 1000;
	in.mask = FAN_OPEN;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 1010;
	in.mask = FAN_MODIFY;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 1050;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 1100;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 1140;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 1700;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 1750;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);

	char *captured = slurp_fd(out.file_fd);
	CHECK(captured != NULL);
	if (captured) {
		CHECK(count_substr(captured, "\"kind\":\"burst\"") == 2);
		CHECK_CONTAINS(captured, "\"count\":2,\"window_ms\":100");
	}
	free(captured);

	policy_free(policy);
	out_free(&out);
	CHECK(unlink(path) == 0);
}

static void test_policy_deny_only_on_perm_events(void)
{
	struct out_sink out;
	char path[] = "/tmp/fanotifyd-capture-XXXXXX";
	char canary_pattern[] = "/tmp/canary*";
	char *canaries[] = { canary_pattern };
	struct policy_cfg cfg = {
		.canaries = canaries,
		.n_canaries = 1,
		.burst_threshold = 2,
		.burst_window_ms = 100,
		.hook_cooldown_ms = 500,
		.deny_on_alert = 1,
	};

	if (init_capture_sink(&out, path, sizeof path) < 0) {
		CHECK(0);
		return;
	}

	struct policy_state *policy = policy_new(&cfg, &out);
	CHECK(policy != NULL);
	if (!policy) {
		out_free(&out);
		unlink(path);
		return;
	}

	struct policy_input in = {
		.ts_ms = 100,
		.pid = 42,
		.path = "/tmp/canary",
	};

	in.mask = FAN_OPEN;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 700;
	in.mask = FAN_OPEN_PERM;
	CHECK(policy_on_event(policy, &in) == FAN_DENY);

	struct policy_input burst_in = {
		.pid = 7,
		.path = "/tmp/data",
	};
	burst_in.ts_ms = 1000;
	burst_in.mask = FAN_MODIFY;
	CHECK(policy_on_event(policy, &burst_in) == FAN_ALLOW);
	burst_in.ts_ms = 1050;
	CHECK(policy_on_event(policy, &burst_in) == FAN_ALLOW);

	char *captured = slurp_fd(out.file_fd);
	CHECK(captured != NULL);
	if (captured) {
		CHECK(count_substr(captured, "\"kind\":\"canary\"") == 2);
		CHECK(count_substr(captured, "\"reason\":\"canary opened\"") == 2);
		CHECK(count_substr(captured, "\"kind\":\"burst\"") == 1);
		CHECK_CONTAINS(captured, "\"count\":2,\"window_ms\":100");
	}
	free(captured);

	policy_free(policy);
	out_free(&out);
	CHECK(unlink(path) == 0);
}

static void test_policy_burst_window_reset_and_gc(void)
{
	struct out_sink out;
	char path[] = "/tmp/fanotifyd-capture-XXXXXX";
	struct policy_cfg cfg = {
		.burst_threshold = 2,
		.burst_window_ms = 100,
		.hook_cooldown_ms = 50,
	};

	if (init_capture_sink(&out, path, sizeof path) < 0) {
		CHECK(0);
		return;
	}

	struct policy_state *policy = policy_new(&cfg, &out);
	CHECK(policy != NULL);
	if (!policy) {
		out_free(&out);
		unlink(path);
		return;
	}

	struct policy_input in = {
		.pid = 8,
		.mask = FAN_MODIFY,
		.path = "/tmp/data",
	};
	in.ts_ms = 1000;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	CHECK(policy_window_count(policy) == 1);
	in.ts_ms = 1201;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);

	char *captured = slurp_fd(out.file_fd);
	CHECK(captured != NULL);
	if (captured)
		CHECK(count_substr(captured, "\"kind\":\"burst\"") == 0);
	free(captured);

	policy_tick(policy, 61202);
	CHECK(policy_window_count(policy) == 0);

	policy_free(policy);
	out_free(&out);
	CHECK(unlink(path) == 0);
}

static void test_policy_canary_hook_cooldown(void)
{
	struct out_sink out;
	char path[] = "/tmp/fanotifyd-capture-XXXXXX";
	char canary_pattern[] = "/tmp/canary";
	char *canaries[] = { canary_pattern };
	struct policy_cfg cfg = {
		.canaries = canaries,
		.n_canaries = 1,
		.hook_cooldown_ms = 10000,
	};

	if (init_capture_sink(&out, path, sizeof path) < 0) {
		CHECK(0);
		return;
	}

	struct policy_state *policy = policy_new(&cfg, &out);
	CHECK(policy != NULL);
	if (!policy) {
		out_free(&out);
		unlink(path);
		return;
	}

	struct policy_input in = {
		.pid = 42,
		.mask = FAN_OPEN,
		.path = "/tmp/canary",
	};
	in.ts_ms = 100;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 110;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);

	char *captured = slurp_fd(out.file_fd);
	CHECK(captured != NULL);
	if (captured)
		CHECK(count_substr(captured, "\"kind\":\"canary\"") == 1);
	free(captured);

	policy_free(policy);
	out_free(&out);
	CHECK(unlink(path) == 0);
}

static void test_policy_canary_hook_cooldown_runs_hook(void)
{
	struct out_sink out;
	char path[] = "/tmp/fanotifyd-capture-XXXXXX";
	char hook_out[] = "/tmp/fanotifyd-hook-XXXXXX";
	int hfd = mkstemp(hook_out);
	CHECK(hfd >= 0);
	if (hfd < 0)
		return;
	close(hfd);

	char canary_pattern[] = "/tmp/canary";
	char *canaries[] = { canary_pattern };
	char hook_cmd[256];
	snprintf(hook_cmd, sizeof hook_cmd,
	         "printf '%%s:%%s:%%s:%%s\\n' \"$FAN_KIND\" \"$FAN_PID\" "
	         "\"$FAN_REASON\" \"$FAN_PATH\" >> %s",
	         hook_out);

	struct policy_cfg cfg = {
		.canaries = canaries,
		.n_canaries = 1,
		.hook_cmd = hook_cmd,
		.hook_cooldown_ms = 500,
	};

	if (init_capture_sink(&out, path, sizeof path) < 0) {
		CHECK(0);
		unlink(hook_out);
		return;
	}

	struct policy_state *policy = policy_new(&cfg, &out);
	CHECK(policy != NULL);
	if (!policy) {
		out_free(&out);
		unlink(path);
		unlink(hook_out);
		return;
	}

	struct policy_input in = {
		.pid = 42,
		.mask = FAN_OPEN,
		.path = "/tmp/canary",
	};
	in.ts_ms = 1000;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 1100;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.ts_ms = 1600;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);

	int status;
	while (waitpid(-1, &status, 0) > 0)
		;

	char *captured = slurp_fd(out.file_fd);
	CHECK(captured != NULL);
	if (captured) {
		CHECK(count_substr(captured, "\"kind\":\"canary\"") == 2);
		CHECK(count_substr(captured, "\"reason\":\"canary opened\"") == 2);
		CHECK(count_substr(captured, "\"path\":\"/tmp/canary\"") == 2);
	}
	free(captured);

	int rfd = open(hook_out, O_RDONLY);
	CHECK(rfd >= 0);
	if (rfd >= 0) {
		char *hook_content = slurp_fd(rfd);
		close(rfd);
		CHECK(hook_content != NULL);
		if (hook_content)
			CHECK(count_substr(hook_content,
			                   "canary:42:canary opened:/tmp/canary") == 2);
		free(hook_content);
	}

	policy_free(policy);
	out_free(&out);
	CHECK(unlink(path) == 0);
	CHECK(unlink(hook_out) == 0);
}

static void test_config_load_file_rejects_invalid_u32(void)
{
	const char *keys[] = {
		"burst_threshold",
		"burst_window_ms",
		"hook_cooldown_ms",
	};
	const char *bad_vals[] = { "abc", "12ms", "-1", "4294967296" };

	for (size_t k = 0; k < sizeof keys / sizeof keys[0]; k++) {
		for (size_t v = 0; v < sizeof bad_vals / sizeof bad_vals[0]; v++) {
			char path[] = "/tmp/fanotifyd-config-XXXXXX";
			char contents[128];
			snprintf(contents, sizeof contents, "%s %s\n",
			         keys[k], bad_vals[v]);

			if (write_temp_config(path, sizeof path, contents) < 0) {
				CHECK(0);
				continue;
			}

			struct daemon_cfg cfg;
			daemon_cfg_init(&cfg);
			CHECK(daemon_cfg_load_file(&cfg, path) == -1);
			daemon_cfg_free(&cfg);
			CHECK(unlink(path) == 0);
		}
	}
}

static void test_config_load_file_accepts_valid_u32(void)
{
	struct daemon_cfg cfg;
	char path[] = "/tmp/fanotifyd-config-XXXXXX";
	const char *contents =
		"burst_threshold 0\n"
		"burst_window_ms 1500\n"
		"hook_cooldown_ms 4294967295\n";

	if (write_temp_config(path, sizeof path, contents) < 0) {
		CHECK(0);
		return;
	}

	daemon_cfg_init(&cfg);
	CHECK(daemon_cfg_load_file(&cfg, path) == 0);
	CHECK(cfg.burst_threshold == 0);
	CHECK(cfg.burst_window_ms == 1500);
	CHECK(cfg.hook_cooldown_ms == 4294967295U);
	daemon_cfg_free(&cfg);
	CHECK(unlink(path) == 0);
}

static void test_config_load_file_rejects_invalid_bool(void)
{
	const char *keys[] = {
		"foreground",
		"perm",
		"deny_on_alert",
		"fid",
	};
	const char *bad_vals[] = { "true", "false", "2", "-1", "1junk" };

	for (size_t k = 0; k < sizeof keys / sizeof keys[0]; k++) {
		for (size_t v = 0; v < sizeof bad_vals / sizeof bad_vals[0]; v++) {
			char path[] = "/tmp/fanotifyd-config-XXXXXX";
			char contents[128];
			snprintf(contents, sizeof contents, "%s %s\n",
			         keys[k], bad_vals[v]);

			if (write_temp_config(path, sizeof path, contents) < 0) {
				CHECK(0);
				continue;
			}

			struct daemon_cfg cfg;
			daemon_cfg_init(&cfg);
			CHECK(daemon_cfg_load_file(&cfg, path) == -1);
			daemon_cfg_free(&cfg);
			CHECK(unlink(path) == 0);
		}
	}
}

static void test_config_load_file_accepts_valid_bool(void)
{
	const char *keys[] = {
		"foreground",
		"perm",
		"deny_on_alert",
		"fid",
	};
	const char *good_vals[] = { "0", "1" };

	for (size_t k = 0; k < sizeof keys / sizeof keys[0]; k++) {
		for (size_t v = 0; v < sizeof good_vals / sizeof good_vals[0]; v++) {
			char path[] = "/tmp/fanotifyd-config-XXXXXX";
			char contents[128];
			snprintf(contents, sizeof contents, "%s %s\n",
			         keys[k], good_vals[v]);

			if (write_temp_config(path, sizeof path, contents) < 0) {
				CHECK(0);
				continue;
			}

			struct daemon_cfg cfg;
			daemon_cfg_init(&cfg);
			CHECK(daemon_cfg_load_file(&cfg, path) == 0);
			daemon_cfg_free(&cfg);
			CHECK(unlink(path) == 0);
		}
	}
}

static void test_parse_argv_rejects_invalid_u32(void)
{
	const char *flags[] = {
		"--burst-threshold",
		"--burst-window-ms",
		"--hook-cooldown-ms",
	};
	const char *bad_vals[] = { "abc", "12ms", "-1", "4294967296" };

	for (size_t f = 0; f < sizeof flags / sizeof flags[0]; f++) {
		for (size_t v = 0; v < sizeof bad_vals / sizeof bad_vals[0]; v++) {
			optind = 0;
			char *argv[] = {
				(char *)"fanotifyd",
				(char *)flags[f],
				(char *)bad_vals[v],
				NULL,
			};
			struct daemon_cfg cfg;
			daemon_cfg_init(&cfg);
			CHECK(daemon_cfg_parse_argv(&cfg, 3, argv) == -1);
			daemon_cfg_free(&cfg);
		}
	}
}

static void test_parse_argv_accepts_valid_u32(void)
{
	optind = 0;
	char *argv[] = {
		(char *)"fanotifyd",
		(char *)"--burst-threshold", (char *)"0",
		(char *)"--burst-window-ms", (char *)"250",
		(char *)"--hook-cooldown-ms", (char *)"4294967295",
		NULL,
	};
	struct daemon_cfg cfg;
	daemon_cfg_init(&cfg);
	CHECK(daemon_cfg_parse_argv(&cfg, 7, argv) == 0);
	CHECK(cfg.burst_threshold == 0);
	CHECK(cfg.burst_window_ms == 250);
	CHECK(cfg.hook_cooldown_ms == 4294967295U);
	daemon_cfg_free(&cfg);
}

static void test_parse_argv_propagates_add_failures(void)
{
	const char *mark_flags[] = { "-w", "--mount", "--filesystem" };

	for (size_t i = 0; i < sizeof mark_flags / sizeof mark_flags[0]; i++) {
		optind = 0;
		char *argv[] = {
			(char *)"fanotifyd",
			(char *)mark_flags[i],
			(char *)"/tmp",
			NULL,
		};
		struct daemon_cfg cfg;
		daemon_cfg_init(&cfg);
		daemon_cfg_test_fail_next_mark_add();
		CHECK(daemon_cfg_parse_argv(&cfg, 3, argv) == -1);
		CHECK(cfg.n_marks == 0);
		daemon_cfg_free(&cfg);
	}

	optind = 0;
	char *argv[] = {
		(char *)"fanotifyd",
		(char *)"--canary",
		(char *)"/tmp/fanotifyd-canary",
		NULL,
	};
	struct daemon_cfg cfg;
	daemon_cfg_init(&cfg);
	daemon_cfg_test_fail_next_canary_add();
	CHECK(daemon_cfg_parse_argv(&cfg, 3, argv) == -1);
	CHECK(cfg.n_canaries == 0);
	daemon_cfg_free(&cfg);
}

static void test_output_subscriber_closed_no_sigpipe(void)
{
	struct sigaction sa = { .sa_handler = SIG_DFL };
	sigemptyset(&sa.sa_mask);
	CHECK(sigaction(SIGPIPE, &sa, NULL) == 0);

	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	struct out_sink out;
	out_init(&out);
	out.sub_fds = malloc(sizeof *out.sub_fds);
	CHECK(out.sub_fds != NULL);
	out.sub_cap = 1;
	out.sub_fds[0] = sv[0];
	out.sub_len = 1;

	close(sv[1]);

	const char line[] = "hello";
	CHECK(out_emit_line(&out, line, sizeof line - 1) == 0);
	CHECK(out.sub_len == 0);

	out_free(&out);
}

static void test_output_accept_caps_subscribers(void)
{
	char path[] = "/tmp/fanotifyd-out-XXXXXX";
	int tfd = mkstemp(path);
	if (tfd < 0) { CHECK(0); return; }
	close(tfd);
	unlink(path);

	struct out_sink out;
	out_init(&out);
	CHECK(out_open_socket(&out, path) == 0);

	enum { N_EXTRA = 5 };
	const int total_clients = OUT_MAX_SUBSCRIBERS + N_EXTRA;
	int clients[OUT_MAX_SUBSCRIBERS + N_EXTRA];

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);

	for (int i = 0; i < total_clients; i++) {
		clients[i] = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
		CHECK(clients[i] >= 0);
		int rc = connect(clients[i], (struct sockaddr *)&addr, sizeof addr);
		CHECK(rc == 0 || errno == EINPROGRESS);

		if ((i + 1) % 8 == 0)
			CHECK(out_accept(&out) == 0);
	}
	CHECK(out_accept(&out) == 0);

	CHECK(out.sub_len == OUT_MAX_SUBSCRIBERS);

	const char line[] = "ping";
	CHECK(out_emit_line(&out, line, sizeof line - 1) == 0);
	CHECK(out.sub_len == OUT_MAX_SUBSCRIBERS);

	for (int i = 0; i < OUT_MAX_SUBSCRIBERS; i++) {
		char rbuf[16];
		ssize_t r = recv(clients[i], rbuf, sizeof rbuf, MSG_DONTWAIT);
		CHECK(r > 0);
	}
	for (int i = OUT_MAX_SUBSCRIBERS; i < total_clients; i++) {
		char rbuf[16];
		ssize_t r = recv(clients[i], rbuf, sizeof rbuf, MSG_DONTWAIT);
		CHECK(r == 0);
	}

	for (int i = 0; i < total_clients; i++)
		close(clients[i]);
	out_free(&out);
}

static int count_open_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	if (!d) return -1;
	int count = 0;
	struct dirent *e;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] != '.')
			count++;
	}
	closedir(d);
	return count;
}

static int redirect_stderr_to_file(int *saved_fd_out, char path[], size_t pathsz)
{
	snprintf(path, pathsz, "/tmp/fanotifyd-stderr-XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0) return -1;
	fflush(stderr);
	int saved = dup(STDERR_FILENO);
	if (saved < 0) { close(fd); unlink(path); return -1; }
	if (dup2(fd, STDERR_FILENO) < 0) {
		close(saved); close(fd); unlink(path); return -1;
	}
	close(fd);
	*saved_fd_out = saved;
	return 0;
}

static void restore_stderr(int saved_fd)
{
	fflush(stderr);
	dup2(saved_fd, STDERR_FILENO);
	close(saved_fd);
}

static char *read_file_to_string(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return NULL;
	char *c = slurp_fd(fd);
	close(fd);
	return c;
}

static int fail_signalfd(int fd, const sigset_t *mask, int flags)
{
	(void)fd; (void)mask; (void)flags;
	errno = EMFILE;
	return -1;
}

static int fail_timerfd_create(int clockid, int flags)
{
	(void)clockid; (void)flags;
	errno = EMFILE;
	return -1;
}

static int fail_timerfd_settime(int fd, int flags,
                                const struct itimerspec *nv,
                                struct itimerspec *ov)
{
	(void)fd; (void)flags; (void)nv; (void)ov;
	errno = EINVAL;
	return -1;
}

static int fail_epoll_create1(int flags)
{
	(void)flags;
	errno = ENOMEM;
	return -1;
}

static int fail_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	(void)epfd; (void)op; (void)fd; (void)event;
	errno = ENOSPC;
	return -1;
}

static void run_event_loop_setup_fault(const struct event_loop_syscalls *sc,
                                       int expected_errno,
                                       const char *expected_token)
{
	int fanfd = open("/dev/null", O_RDONLY);
	CHECK(fanfd >= 0);
	if (fanfd < 0) return;

	int baseline = count_open_fds();

	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);

	int saved_stderr = -1;
	char log_path[64];
	if (redirect_stderr_to_file(&saved_stderr, log_path, sizeof log_path) < 0) {
		CHECK(0);
		close(fanfd);
		return;
	}

	int sigfd = -1, tickfd = -1, ep = -1;
	int rc = daemon_setup_event_loop(sc, &mask, fanfd, -1,
	                                 &sigfd, &tickfd, &ep);
	int saved_errno = errno;

	restore_stderr(saved_stderr);

	CHECK(rc == -1);
	CHECK(saved_errno == expected_errno);
	CHECK(count_open_fds() == baseline);

	char *log = read_file_to_string(log_path);
	CHECK(log != NULL);
	if (log) {
		CHECK_CONTAINS(log, expected_token);
		CHECK_CONTAINS(log, strerror(expected_errno));
	}
	free(log);
	unlink(log_path);

	close(fanfd);
}

static void test_daemon_setup_event_loop_signalfd_fails(void)
{
	struct event_loop_syscalls sc = daemon_default_syscalls;
	sc.signalfd = fail_signalfd;
	run_event_loop_setup_fault(&sc, EMFILE, "signalfd");
}

static void test_daemon_setup_event_loop_timerfd_create_fails(void)
{
	struct event_loop_syscalls sc = daemon_default_syscalls;
	sc.timerfd_create = fail_timerfd_create;
	run_event_loop_setup_fault(&sc, EMFILE, "timerfd_create");
}

static void test_daemon_setup_event_loop_timerfd_settime_fails(void)
{
	struct event_loop_syscalls sc = daemon_default_syscalls;
	sc.timerfd_settime = fail_timerfd_settime;
	run_event_loop_setup_fault(&sc, EINVAL, "timerfd_settime");
}

static void test_daemon_setup_event_loop_epoll_create1_fails(void)
{
	struct event_loop_syscalls sc = daemon_default_syscalls;
	sc.epoll_create1 = fail_epoll_create1;
	run_event_loop_setup_fault(&sc, ENOMEM, "epoll_create1");
}

static void test_daemon_setup_event_loop_epoll_ctl_fails(void)
{
	struct event_loop_syscalls sc = daemon_default_syscalls;
	sc.epoll_ctl = fail_epoll_ctl;
	run_event_loop_setup_fault(&sc, ENOSPC, "epoll_ctl");
}

int main(void)
{
	test_json_escape();
	test_rstrip_slash();
	test_config_load_file();
	test_config_load_job_registry();
	test_config_load_job_registry_rejects_malformed_entry();
	test_config_load_file_rejects_unknown_key();
	test_config_load_file_rejects_missing_value();
	test_job_classify_path();
	test_output_event_json();
	test_output_alert_overflow_with_path();
	test_output_alert_overflow_no_optional_fields();
	test_fan_compute_mark_mask();
	test_fan_mask_str();
	test_fan_mask_str_contract();
	test_policy_canary_alerts();
	test_policy_burst_behavior();
	test_policy_deny_only_on_perm_events();
	test_policy_burst_window_reset_and_gc();
	test_policy_canary_hook_cooldown();
	test_policy_canary_hook_cooldown_runs_hook();
	test_config_load_file_rejects_invalid_u32();
	test_config_load_file_accepts_valid_u32();
	test_config_load_file_rejects_invalid_bool();
	test_config_load_file_accepts_valid_bool();
	test_parse_argv_rejects_invalid_u32();
	test_parse_argv_accepts_valid_u32();
	test_parse_argv_propagates_add_failures();
	test_output_subscriber_closed_no_sigpipe();
	test_output_accept_caps_subscribers();
	test_daemon_setup_event_loop_signalfd_fails();
	test_daemon_setup_event_loop_timerfd_create_fails();
	test_daemon_setup_event_loop_timerfd_settime_fails();
	test_daemon_setup_event_loop_epoll_create1_fails();
	test_daemon_setup_event_loop_epoll_ctl_fails();
	if (failures) {
		fprintf(stderr, "%d test failure(s)\n", failures);
		return 1;
	}
	printf("all unit tests passed\n");
	return 0;
}
