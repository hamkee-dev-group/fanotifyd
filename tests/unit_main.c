#include "config.h"
#include "buf.h"
#include "fan.h"
#include "output.h"
#include "path.h"
#include "policy.h"
#include "util.h"

#include <fcntl.h>
#include <linux/fanotify.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
	            "\"path\":\"/tmp/none\"}");
	out_free(&out);
}

static void test_fan_compute_mark_mask(void)
{
	struct mark_spec mark = {
		.path = "/tmp/x",
		.type = MARK_INODE,
		.mask = 0,
		.children = 0,
	};

	uint64_t mask = fan_compute_mark_mask(&mark, 0);
	CHECK((mask & FAN_OPEN_PERM) == 0);
	CHECK((mask & FAN_ACCESS_PERM) == 0);

	mask = fan_compute_mark_mask(&mark, 1);
	CHECK((mask & FAN_OPEN_PERM) != 0);
	CHECK((mask & FAN_ACCESS_PERM) != 0);

	mark.mask = FAN_OPEN | FAN_DELETE;
	mask = fan_compute_mark_mask(&mark, 1);
	CHECK(mask == (FAN_OPEN | FAN_DELETE));
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
	in.mask = FAN_OPEN;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.mask = FAN_MODIFY;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.mask = FAN_MOVED_FROM;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
	in.mask = FAN_DELETE;
	CHECK(policy_on_event(policy, &in) == FAN_ALLOW);
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
	test_fan_compute_mark_mask();
	test_policy_canary_alerts();
	test_policy_burst_behavior();
	test_policy_burst_window_reset_and_gc();
	test_output_subscriber_closed_no_sigpipe();
	if (failures) {
		fprintf(stderr, "%d test failure(s)\n", failures);
		return 1;
	}
	printf("all unit tests passed\n");
	return 0;
}
