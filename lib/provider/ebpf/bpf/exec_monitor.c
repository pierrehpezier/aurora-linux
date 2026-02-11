// SPDX-License-Identifier: GPL-2.0
// exec_monitor.c — BPF program for tracepoint/sched/sched_process_exec
//
// Captures minimal data per successful execve: pid, ppid, uid, gid, comm, filename.
// All richer fields (cmdline, parent image, username, cwd) are reconstructed in userland.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN  16
#define MAX_FILENAME   256

struct exec_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	char  comm[TASK_COMM_LEN];
	char  filename[MAX_FILENAME];
	__u32 filename_len;
};

// Ring buffer for delivering events to userland.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024); // 8 MB default
} events SEC(".maps");

// Counter for dropped events when ring buffer is full.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	struct exec_event *evt;

	// Reserve space in the ring buffer
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt) {
		// Buffer full: increment lost counter and bail
		__u32 key = 0;
		__u64 *count = bpf_map_lookup_elem(&lost_events, &key);
		if (count)
			__sync_fetch_and_add(count, 1);
		return 0;
	}

	// Timestamp
	evt->timestamp_ns = bpf_ktime_get_ns();

	// PID and PPID
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	evt->pid = pid_tgid >> 32;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent;
	parent = BPF_CORE_READ(task, real_parent);
	evt->ppid = BPF_CORE_READ(parent, tgid);

	// UID and GID
	__u64 uid_gid = bpf_get_current_uid_gid();
	evt->uid = uid_gid & 0xFFFFFFFF;
	evt->gid = uid_gid >> 32;

	// comm (task name, max 16 bytes)
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	// filename from bprm->filename via the tracepoint data
	// The tracepoint provides the filename offset in __data.
	unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
	int ret = bpf_probe_read_kernel_str(
		evt->filename,
		sizeof(evt->filename),
		(void *)ctx + fname_off
	);
	if (ret > 0) {
		evt->filename_len = ret;
	} else {
		evt->filename[0] = '\0';
		evt->filename_len = 0;
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
