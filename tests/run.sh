#!/bin/sh

set -eu

skip() {
	echo "SKIP: $1"
	exit 0
}

fail() {
	echo "FAIL: $1" >&2
	exit 1
}

require_file_contains() {
	file=$1
	needle=$2
	label=$3
	if ! grep -q "$needle" "$file"; then
		fail "missing $label"
	fi
}

wait_for_daemon() {
	pid=$1
	logfile=$2
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		if kill -0 "$pid" 2>/dev/null; then
			return 0
		fi
		sleep 0.1
	done

	if grep -q "fanotify_init failed" "$logfile" 2>/dev/null ||
	   grep -q "fanotify_mark" "$logfile" 2>/dev/null ||
	   grep -q "Operation not permitted" "$logfile" 2>/dev/null; then
		skip "fanotify unavailable on this host"
	fi
	fail "fanotifyd exited during startup"
}

stop_daemon() {
	pid=$1
	if kill -0 "$pid" 2>/dev/null; then
		kill -TERM "$pid" 2>/dev/null || true
		wait "$pid" || true
	fi
}

run_observe_smoke() {
	tmpdir=$1
	watchdir=$tmpdir/watch
	logfile=$tmpdir/observe.log
	outfile=$tmpdir/observe.jsonl
	canary=$watchdir/canary

	mkdir -p "$watchdir"
	: >"$canary"

	./fanotifyd --foreground \
		--watch "$watchdir" \
		--canary "$watchdir/canary*" \
		--output "$outfile" \
		>"$tmpdir/observe.stdout" 2>"$logfile" &
	daemon_pid=$!
	trap 'stop_daemon "$daemon_pid"; rm -rf "$tmpdir"' EXIT INT TERM HUP
	wait_for_daemon "$daemon_pid" "$logfile"
	sleep 0.2

	: >"$watchdir/file"
	cat "$watchdir/file" >/dev/null
	printf 'hello\n' >>"$watchdir/file"
	mv "$watchdir/file" "$watchdir/file.moved"
	rm -f "$watchdir/file.moved"

	cat "$canary" >/dev/null
	if command -v truncate >/dev/null 2>&1; then
		truncate -s 3 "$canary"
		canary_modify_checked=1
	else
		canary_modify_checked=0
	fi
	printf 'secret\n' >>"$canary"
	mv "$canary" "$watchdir/canary.moved"
	rm -f "$watchdir/canary.moved"

	sleep 0.5
	stop_daemon "$daemon_pid"

	require_file_contains "$outfile" '"events":"CREATE' 'CREATE event'
	require_file_contains "$outfile" '"events":"OPEN' 'OPEN event'
	if ! grep -q '"events":"[^"]*MODIFY' "$outfile" &&
	   ! grep -q '"events":"[^"]*CLOSE_WRITE' "$outfile"; then
		fail "missing MODIFY/CLOSE_WRITE event"
	fi
	if ! grep -q '"events":"[^"]*MOVED_FROM' "$outfile" &&
	   ! grep -q '"events":"[^"]*MOVED_TO' "$outfile" &&
	   ! grep -q '"events":"[^"]*RENAME' "$outfile"; then
		fail "missing rename event"
	fi
	require_file_contains "$outfile" '"events":"[^"]*DELETE' 'DELETE event'

	if grep -q 'fid-unresolved' "$outfile"; then
		fail "unresolved file handle in observe output"
	fi
	if grep -q '<unknown>' "$outfile"; then
		fail "unresolved event path in observe output"
	fi
	require_file_contains "$outfile" "\"path\":\"$watchdir/file\"" 'resolved event path'
	require_file_contains "$outfile" '"kind":"canary"' 'canary alert'
	require_file_contains "$outfile" '"reason":"canary opened"' 'canary open alert'
	require_file_contains "$outfile" '"reason":"canary renamed"' 'canary rename alert'
	require_file_contains "$outfile" '"reason":"canary deleted"' 'canary delete alert'
	if [ "$canary_modify_checked" -eq 1 ]; then
		require_file_contains "$outfile" '"reason":"canary modified"' \
			'canary modify alert'
	fi
}

run_perm_smoke() {
	tmpdir=$1
	if [ "$(id -u)" -ne 0 ]; then
		skip "perm smoke requires root"
	fi
	if ! command -v timeout >/dev/null 2>&1; then
		skip "perm smoke requires timeout(1)"
	fi

	watchdir=$tmpdir/perm
	logfile=$tmpdir/perm.log
	outfile=$tmpdir/perm.jsonl
	allowfile=$watchdir/allow
	blockfile=$watchdir/blocked

	mkdir -p "$watchdir"
	mount -t tmpfs tmpfs "$watchdir"
	trap 'stop_daemon "${daemon_pid:-0}"; umount "$watchdir" 2>/dev/null || true; rm -rf "$tmpdir"' EXIT INT TERM HUP
	: >"$allowfile"
	: >"$blockfile"

	./fanotifyd --foreground --perm --deny-on-alert \
		--mount "$watchdir" \
		--canary "$blockfile" \
		--output "$outfile" \
		>"$tmpdir/perm.stdout" 2>"$logfile" &
	daemon_pid=$!
	trap 'stop_daemon "$daemon_pid"; rm -rf "$tmpdir"' EXIT INT TERM HUP
	wait_for_daemon "$daemon_pid" "$logfile"
	sleep 0.2

	timeout 2 cat "$allowfile" >/dev/null || fail "allowed open hung or failed"

	set +e
	timeout 2 cat "$blockfile" >/dev/null 2>"$tmpdir/block.err"
	block_rc=$?
	set -e
	if [ "$block_rc" -eq 124 ]; then
		fail "denied open hung"
	fi
	if [ "$block_rc" -eq 0 ]; then
		fail "denied canary open unexpectedly succeeded"
	fi

	sleep 0.5
	stop_daemon "$daemon_pid"
	umount "$watchdir"

	require_file_contains "$outfile" 'OPEN_PERM' 'permission event'
	require_file_contains "$outfile" '"decision":"allow"' 'allow decision'
	require_file_contains "$outfile" '"decision":"deny"' 'deny decision'
}

run_pivot_mount_smoke() {
	tmpdir=$1
	if [ "$(id -u)" -ne 0 ]; then
		skip "pivot mount smoke requires root"
	fi
	if [ ! -x ./tests/pivot_writer ]; then
		fail "missing tests/pivot_writer helper"
	fi

	rootdir=$tmpdir/pivot-root
	logfile=$tmpdir/pivot.log
	outfile=$tmpdir/pivot.jsonl

	mkdir -p "$rootdir"
	mount -t tmpfs tmpfs "$rootdir"
	mkdir -p "$rootdir/tmp"
	trap 'stop_daemon "${daemon_pid:-0}"; umount "$rootdir" 2>/dev/null || true; rm -rf "$tmpdir"' EXIT INT TERM HUP

	./fanotifyd --foreground \
		--filesystem "$rootdir" \
		--no-fid \
		--output "$outfile" \
		>"$tmpdir/pivot.stdout" 2>"$logfile" &
	daemon_pid=$!
	wait_for_daemon "$daemon_pid" "$logfile"
	sleep 0.2

	./tests/pivot_writer "$rootdir" >"$tmpdir/pivot-writer.stdout" 2>"$tmpdir/pivot-writer.stderr" ||
		fail "pivot writer failed: $(cat "$tmpdir/pivot-writer.stderr")"

	sleep 0.5
	stop_daemon "$daemon_pid"

	require_file_contains "$rootdir/tmp/marker" 'pivot marker' 'pivot marker payload'
	require_file_contains "$outfile" 'marker' 'pivot marker event path'
	if ! grep -q '"events":"[^"]*CREATE' "$outfile" &&
	   ! grep -q '"events":"[^"]*MODIFY' "$outfile" &&
	   ! grep -q '"events":"[^"]*CLOSE_WRITE' "$outfile"; then
		fail "missing pivot marker write event"
	fi

	umount "$rootdir"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT INT TERM HUP

version_output=$(./fanotifyd --version)
[ "$version_output" = "fanotifyd 0.1.0" ] || fail "unexpected version output"

if ./fanotifyd --bad-flag >"$tmpdir/bad-flag.out" 2>&1; then
	fail "--bad-flag unexpectedly succeeded"
fi
require_file_contains "$tmpdir/bad-flag.out" 'Usage:' 'usage output'

printf 'output\n' >"$tmpdir/bad.conf"
if ./fanotifyd -c "$tmpdir/bad.conf" >"$tmpdir/bad-config.out" 2>&1; then
	fail "invalid config unexpectedly succeeded"
fi
require_file_contains "$tmpdir/bad-config.out" 'failed to load config' 'config failure output'

if [ "$(id -u)" -ne 0 ]; then
	skip "integration smoke requires root/CAP_SYS_ADMIN for fanotify"
fi

run_observe_smoke "$tmpdir"
run_pivot_mount_smoke "$tmpdir"
run_perm_smoke "$tmpdir"

echo "integration smoke tests passed"
