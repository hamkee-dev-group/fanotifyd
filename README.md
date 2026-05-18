# fanotifyd

`fanotifyd` is a small Linux filesystem event and policy daemon built directly
on `fanotify(7)`. It turns kernel filesystem notifications into JSON Lines and
can optionally make allow/deny decisions for permission events.

The project is aimed at the parts of endpoint monitoring where repeated tree
scans are a poor fit: canary files, ransomware-style write bursts, DLP hooks,
job sandboxes, sync/index pipelines, and other places where "what changed?"
should come from the kernel instead of a crawler.

## What it does

- Watches paths with inode, mount, or filesystem fanotify marks.
- Emits structured JSONL records for file events.
- Streams the same records to optional Unix socket subscribers.
- Tags events with `job_id` and `path_role` when paths belong to a configured
  job root, workspace, export directory, or cache.
- Detects canary file access or mutation with exact paths or glob patterns.
- Detects bursts of mutating events per process.
- Runs a shell hook on alerts.
- In permission mode, can deny events that trigger alerts.

This is Linux-only software. It uses fanotify directly, so normal operation
usually requires root or `CAP_SYS_ADMIN`.

## Build

```sh
make
```

That produces:

```text
./fanotifyd
```

Install with:

```sh
sudo make install
```

The default install prefix is `/usr/local`. Override it in the usual `make`
style:

```sh
make PREFIX=/usr
sudo make PREFIX=/usr install
```

## Quick start

Create a directory to watch:

```sh
mkdir -p /tmp/fanotifyd-demo
touch /tmp/fanotifyd-demo/canary
```

Run the daemon in the foreground and write events to stdout:

```sh
sudo ./fanotifyd --foreground \
  --watch /tmp/fanotifyd-demo \
  --canary '/tmp/fanotifyd-demo/canary*' \
  --output -
```

Then, from another shell:

```sh
echo hello >/tmp/fanotifyd-demo/file
cat /tmp/fanotifyd-demo/canary >/dev/null
```

You should see JSONL records like:

```json
{"schema_version":1,"type":"event","ts_ms":1760000000000,"mask":32,"events":"OPEN","decision":"observe","job_id":null,"path_role":null,"pid":1234,"comm":"cat","exe":"/usr/bin/cat","path":"/tmp/fanotifyd-demo/canary"}
{"type":"alert","ts_ms":1760000000001,"kind":"canary","pid":1234,"comm":"cat","exe":"/usr/bin/cat","path":"/tmp/fanotifyd-demo/canary","reason":"canary opened"}
```

## Configuration

`fanotifyd` accepts command-line flags or a simple config file. Config files are
line-oriented: one `key value` pair per line, with `#` comments.

Example:

```text
output /var/log/fanotifyd/J.jsonl
socket /run/fanotifyd/J.sock
foreground 1
perm 1
deny_on_alert 1
burst_threshold 32
burst_window_ms 1000
hook_cooldown_ms 5000

job J
rootfs /run/jobs/J/root
workspace /run/jobs/J/workspace
export /run/jobs/J/export
cache /var/cache/job-platform

mount /run/jobs/J/root
mount /run/jobs/J/workspace
mount /run/jobs/J/export
mount /var/cache/job-platform
canary /run/jobs/J/root/etc/shadow
```

Run it with:

```sh
sudo ./fanotifyd --config examples/cgroupd-landlockd.conf
```

See [examples/cgroupd-landlockd.md](examples/cgroupd-landlockd.md) for a more
complete host-side example.

## Common options

```text
-c, --config FILE          load config from FILE
-w, --watch PATH           watch a directory inode, including child events
    --mount PATH           mark a whole mount
    --filesystem PATH      mark a whole filesystem
    --canary PATTERN       alert on matching canary path; repeatable
-o, --output PATH          write JSONL events to PATH; "-" means stdout
    --socket PATH          Unix socket for streaming subscribers
    --hook CMD             run shell command when an alert fires
    --pid-file PATH        write daemon pid on start
    --burst-threshold N    alert after N mutating events per process/window
    --burst-window-ms MS   burst window; default 1000
    --hook-cooldown-ms MS  per-process alert cooldown; default 5000
-f, --foreground           do not daemonize
    --perm                 use fanotify permission events
    --deny-on-alert        deny permission events that trigger an alert
    --no-fid               use FD mode instead of FID mode
-v, --verbose              increase log verbosity
-h, --help                 show built-in help
    --version              show version
```

## Watch modes

`--watch PATH` uses an inode mark. It is useful for a specific directory and its
direct child events.

`--mount PATH` marks the mount containing `PATH`. This is usually the right
choice for job roots, containers, chroots, or workloads that may write deeper in
the tree after changing root.

`--filesystem PATH` marks the whole filesystem containing `PATH`, where the
kernel supports `FAN_MARK_FILESYSTEM`.

In normal observe mode, fanotifyd prefers FID reporting so it can emit names for
directory-entry events. Permission mode requires FD-based events, so FID
reporting is disabled there.

## Alerts and policy

Canaries are path patterns checked with `fnmatch(3)` semantics. A canary alert
fires when a matching path is opened, modified, renamed, or deleted.

Burst detection counts mutating events per process inside a sliding window.
Set `burst_threshold` to `0` to disable it.

Hooks run through `/bin/sh -c` with these environment variables:

```text
FAN_KIND
FAN_PID
FAN_COMM
FAN_EXE
FAN_PATH
FAN_REASON
```

With `--perm --deny-on-alert`, permission events that produce an alert are
answered with `FAN_DENY`; other permission events are allowed.

## Output

Event records are JSON Lines. The event schema currently includes:

```text
schema_version
type
ts_ms
mask
events
decision
job_id
path_role
pid
comm
exe
path
name
is_dir
```

Alert records include:

```text
type
ts_ms
kind
pid
comm
exe
path
reason
```

For burst alerts, the record also includes `count` and `window_ms`.

The `kind` field identifies the alert category (e.g. `canary`, `burst`,
`overflow`). For `overflow` alerts emitted when the fanotify queue
overflows, `pid` is `0`, `path` is `<overflow>`, `reason` is
`fanotify queue overflowed`, and `comm`/`exe` are omitted.

## Tests

Unit tests do not need root:

```sh
make test
```

Integration tests exercise real fanotify behavior and require root or the right
capabilities:

```sh
sudo make integration
```

The integration script skips cleanly when fanotify is not available on the host.
