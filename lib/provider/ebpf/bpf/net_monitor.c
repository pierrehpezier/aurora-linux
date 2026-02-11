// SPDX-License-Identifier: GPL-2.0
// net_monitor.c — BPF program for tracepoint/sock/inet_sock_set_state
//
// Traces TCP connection establishment (both outbound and inbound) by observing
// socket state transitions.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET  2
#define AF_INET6 10

// TCP states relevant for connection detection
#define TCP_CLOSE     7
#define TCP_SYN_SENT  2
#define TCP_SYN_RECV  3
#define TCP_ESTABLISHED 1

struct net_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	__u16 sport;
	__u16 dport;
	__u8  saddr[16]; // IPv4 stored as v4-mapped-v6 in bytes 12-15
	__u8  daddr[16];
	__u8  family;    // AF_INET or AF_INET6
	__u8  initiated; // 1 = outbound (SYN_SENT), 0 = inbound
	__u16 _pad;
};

// Ring buffer for network events
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); // 4 MB
} net_events SEC(".maps");

// Lost event counter
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} net_lost_events SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
	int oldstate = ctx->oldstate;
	int newstate = ctx->newstate;

	__u8 initiated;
	if (oldstate == TCP_CLOSE && newstate == TCP_SYN_SENT) {
		initiated = 1; // outbound connection
	} else if (oldstate == TCP_SYN_RECV && newstate == TCP_ESTABLISHED) {
		initiated = 0; // inbound connection accepted
	} else {
		return 0; // not a connection event
	}

	struct net_event *evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt) {
		__u32 key = 0;
		__u64 *count = bpf_map_lookup_elem(&net_lost_events, &key);
		if (count)
			__sync_fetch_and_add(count, 1);
		return 0;
	}

	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->pid = bpf_get_current_pid_tgid() >> 32;
	evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	evt->family = ctx->family;
	evt->sport = ctx->sport;
	evt->dport = ctx->dport;
	evt->initiated = initiated;

	if (ctx->family == AF_INET) {
		// Store as v4-mapped-v6: ::ffff:a.b.c.d
		__builtin_memset(evt->saddr, 0, 10);
		evt->saddr[10] = 0xff;
		evt->saddr[11] = 0xff;
		__builtin_memcpy(&evt->saddr[12], &ctx->saddr, 4);

		__builtin_memset(evt->daddr, 0, 10);
		evt->daddr[10] = 0xff;
		evt->daddr[11] = 0xff;
		__builtin_memcpy(&evt->daddr[12], &ctx->daddr, 4);
	} else {
		__builtin_memcpy(evt->saddr, &ctx->saddr_v6, 16);
		__builtin_memcpy(evt->daddr, &ctx->daddr_v6, 16);
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
