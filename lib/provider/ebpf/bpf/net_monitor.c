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
	int oldstate = BPF_CORE_READ(ctx, oldstate);
	int newstate = BPF_CORE_READ(ctx, newstate);
	__u16 family = BPF_CORE_READ(ctx, family);
	__u16 sport = BPF_CORE_READ(ctx, sport);
	__u16 dport = BPF_CORE_READ(ctx, dport);

	__u8 initiated;
	if (oldstate == TCP_CLOSE && newstate == TCP_SYN_SENT) {
		initiated = 1; // outbound connection
	} else if (oldstate == TCP_SYN_RECV && newstate == TCP_ESTABLISHED) {
		initiated = 0; // inbound connection accepted
	} else {
		return 0; // not a connection event
	}

	if (family != AF_INET && family != AF_INET6)
		return 0;

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
	evt->family = (__u8)family;
	evt->sport = sport;
	evt->dport = dport;
	evt->initiated = initiated;

	if (family == AF_INET) {
		__u32 saddr4 = 0;
		__u32 daddr4 = 0;
		BPF_CORE_READ_INTO(&saddr4, ctx, saddr);
		BPF_CORE_READ_INTO(&daddr4, ctx, daddr);

		// Store as v4-mapped-v6: ::ffff:a.b.c.d
		__builtin_memset(evt->saddr, 0, 10);
		evt->saddr[10] = 0xff;
		evt->saddr[11] = 0xff;
		__builtin_memcpy(&evt->saddr[12], &saddr4, sizeof(saddr4));

		__builtin_memset(evt->daddr, 0, 10);
		evt->daddr[10] = 0xff;
		evt->daddr[11] = 0xff;
		__builtin_memcpy(&evt->daddr[12], &daddr4, sizeof(daddr4));
	} else {
		__u8 saddr6[16] = {};
		__u8 daddr6[16] = {};
		BPF_CORE_READ_INTO(saddr6, ctx, saddr_v6);
		BPF_CORE_READ_INTO(daddr6, ctx, daddr_v6);
		__builtin_memcpy(evt->saddr, saddr6, sizeof(saddr6));
		__builtin_memcpy(evt->daddr, daddr6, sizeof(daddr6));
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
