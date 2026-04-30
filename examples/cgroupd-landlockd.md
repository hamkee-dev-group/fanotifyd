# cgroupd + landlockd Example

This repository does not ship `cgroupd` or `landlockd`, but the example below
shows the intended host-side wiring for a single job `J`.

1. Prepare the job paths.

```sh
mkdir -p /run/jobs/J/root /run/jobs/J/workspace /run/jobs/J/export
cp examples/cgroupd-landlockd.conf /tmp/fanotifyd-J.conf
```

2. Start `fanotifyd` before the workload so prepare-time and runtime writes are
   both observable. The example config uses `mount` marks for job roots because
   inode `watch` marks only cover the marked directory and its direct children;
   a workload pivoted into the job root can write deeper paths such as
   `/tmp/marker`.

```sh
./fanotifyd --config /tmp/fanotifyd-J.conf
```

3. Launch the workload under the rest of the platform pipeline.

```sh
cgroupd run --job-id J -- \
  landlockd run --root /run/jobs/J/root -- \
  /run/jobs/J/root/bin/sh -lc 'echo hello >/workspace/out.txt'
```

4. Subscribe to the socket or tail the JSONL output.

```sh
tail -f /var/log/fanotifyd/J.jsonl
```

Expected event records include `job_id:"J"`, `path_role` values such as
`rootfs`, `workspace`, `export`, or `cache`, and `decision:"allow"`/`"deny"`
when `--perm` is enabled.
