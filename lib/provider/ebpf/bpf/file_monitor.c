// SPDX-License-Identifier: GPL-2.0
// file_monitor.c — BPF programs for tracepoint/syscalls/sys_{enter,exit}_openat
//
// Traces file creation by pairing sys_enter_openat (capture filename + flags)
// with sys_exit_openat (check return value). Only O_CREAT opens that succeed
// are emitted.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_FILENAME     256
#define MAX_WATCHED_DIRS 32
#define O_CREAT          0100

// Temporary storage for in-flight openat calls, keyed by pid_tgid.
struct file_open_args {
	char  filename[MAX_FILENAME];
	__u32 filename_len;
	__u32 flags;
	__s32 dfd;
};

struct file_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	__s32 dfd;
	__u32 flags;
	char  filename[MAX_FILENAME];
	__u32 filename_len;
};

// Per-CPU hash to correlate enter/exit
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct file_open_args);
} openat_args SEC(".maps");

// Ring buffer for file events
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); // 4 MB
} file_events SEC(".maps");

// Lost event counter
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} file_lost_events SEC(".maps");

// PIDs that should be excluded from telemetry (Aurora itself).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} self_pids SEC(".maps");

// Optional path prefix allowlist. When non-empty, only filenames matching
// a watched prefix are emitted.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_WATCHED_DIRS);
	__type(key, char[64]);
	__type(value, __u8);
} watched_dirs SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	if (bpf_map_lookup_elem(&self_pids, &pid))
		return 0;

	// args: dfd(0), filename(1), flags(2), mode(3)
	int flags = (int)ctx->args[2];

	// Only track opens with O_CREAT
	if (!(flags & O_CREAT))
		return 0;

	struct file_open_args args = {};
	args.flags = flags;
	args.dfd = (int)ctx->args[0];

	const char *fname = (const char *)ctx->args[1];
	int ret = bpf_probe_read_user_str(args.filename, sizeof(args.filename), fname);
	if (ret > 0) {
		args.filename_len = ret;
	} else {
		return 0; // can't read filename, skip
	}

	bpf_map_update_elem(&openat_args, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	if (bpf_map_lookup_elem(&self_pids, &pid))
		return 0;

	// Look up stored args from the enter probe
	struct file_open_args *args = bpf_map_lookup_elem(&openat_args, &pid_tgid);
	if (!args)
		return 0; // not a tracked open

	// Clean up immediately
	bpf_map_delete_elem(&openat_args, &pid_tgid);

	// Check return value: negative = failed
	long retval = ctx->ret;
	if (retval < 0)
		return 0;

	// Reserve ring buffer space
	struct file_event *evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt) {
		__u32 key = 0;
		__u64 *count = bpf_map_lookup_elem(&file_lost_events, &key);
		if (count)
			__sync_fetch_and_add(count, 1);
		return 0;
	}

	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->pid = pid;

	__u64 uid_gid = bpf_get_current_uid_gid();
	evt->uid = uid_gid & 0xFFFFFFFF;

	evt->dfd = args->dfd;
	evt->flags = args->flags;

	__builtin_memcpy(evt->filename, args->filename, MAX_FILENAME);
	evt->filename_len = args->filename_len;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
