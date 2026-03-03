# eBPF Network Security Intelligence Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add deep network security analysis to xtop with 5 Sentinel BPF probes (SYN flood, port scan, DNS monitor, connection rate, outbound tracking) and 4 Watchdog BPF probes (TCP flags, DNS deep, TLS fingerprint, beacon detection), integrated into the RCA engine and Security page UI.

**Architecture:** 5 always-on Sentinel probes do lightweight L1 counting in kernel space (< 1% CPU). When anomaly thresholds fire, 4 Watchdog probes auto-attach for L2/L3 deep inspection via TC ingress hooks and kprobe timing analysis. All results feed into the existing RCA engine with 8 new security evidence signals, 6 attack patterns, 8 causal rules, and 8 narrative templates. The Security page (L) gets 5 new collapsible sections.

**Tech Stack:** Go 1.21+, cilium/ebpf, bpf2go, clang, BPF CO-RE (BTF), TC classifier hooks

---

## Task 1: Model Types

Add all new structs and extend existing types for security intelligence data.

**Files:**
- Modify: `model/metrics.go` (after line ~668 for new types, extend SentinelData at line ~536, extend SecurityMetrics at line ~455)

**Step 1: Add new security intelligence structs**

After the existing `PtraceEventEntry` struct (~line 668) in `model/metrics.go`, add:

```go
// --- Network Security Intelligence types ---

// SynFloodEntry tracks SYN flood indicators per source IP.
type SynFloodEntry struct {
	SrcIP         string  `json:"src_ip"`
	SynCount      uint64  `json:"syn_count"`
	SynAckRetrans uint64  `json:"synack_retrans"`
	HalfOpenRatio float64 `json:"half_open_ratio"`
	Rate          float64 `json:"rate"`
}

// PortScanEntry tracks port scan indicators per source IP.
type PortScanEntry struct {
	SrcIP             string  `json:"src_ip"`
	RSTCount          uint64  `json:"rst_count"`
	UniquePortBuckets int     `json:"unique_port_buckets"`
	DurationSec       float64 `json:"duration_sec"`
	Rate              float64 `json:"rate"`
}

// DNSAnomalyEntry tracks DNS anomalies per PID.
type DNSAnomalyEntry struct {
	PID            int     `json:"pid"`
	Comm           string  `json:"comm"`
	QueryCount     uint64  `json:"query_count"`
	AvgQueryLen    int     `json:"avg_query_len"`
	TotalRespBytes uint64  `json:"total_resp_bytes"`
	QueriesPerSec  float64 `json:"queries_per_sec"`
}

// FlowRateEntry tracks connection rates per PID+destination.
type FlowRateEntry struct {
	PID             int    `json:"pid"`
	Comm            string `json:"comm"`
	DstIP           string `json:"dst_ip"`
	ConnectCount    uint64 `json:"connect_count"`
	CloseCount      uint64 `json:"close_count"`
	UniqueDestCount int    `json:"unique_dest_count"`
	Rate            float64 `json:"rate"`
}

// OutboundEntry tracks egress volume per PID+destination.
type OutboundEntry struct {
	PID         int     `json:"pid"`
	Comm        string  `json:"comm"`
	DstIP       string  `json:"dst_ip"`
	TotalBytes  uint64  `json:"total_bytes"`
	PacketCount uint64  `json:"packet_count"`
	BytesPerSec float64 `json:"bytes_per_sec"`
}

// TCPFlagAnomaly tracks suspicious TCP flag combinations.
type TCPFlagAnomaly struct {
	SrcIP     string `json:"src_ip"`
	FlagCombo string `json:"flag_combo"`
	Count     uint64 `json:"count"`
}

// DNSTunnelIndicator tracks DNS tunneling signals.
type DNSTunnelIndicator struct {
	PID         int     `json:"pid"`
	Comm        string  `json:"comm"`
	DomainHash  string  `json:"domain_hash"`
	TXTRatio    float64 `json:"txt_ratio"`
	AvgQueryLen int     `json:"avg_query_len"`
	QueryRate   float64 `json:"query_rate"`
}

// JA3Entry tracks TLS fingerprint occurrences.
type JA3Entry struct {
	Hash      string `json:"hash"`
	Count     uint64 `json:"count"`
	SampleSrc string `json:"sample_src"`
	SampleDst string `json:"sample_dst"`
	Known     string `json:"known"`
}

// BeaconIndicator tracks C2 beacon timing patterns.
type BeaconIndicator struct {
	PID            int     `json:"pid"`
	Comm           string  `json:"comm"`
	DstIP          string  `json:"dst_ip"`
	DstPort        uint16  `json:"dst_port"`
	AvgIntervalSec float64 `json:"avg_interval_sec"`
	Jitter         float64 `json:"jitter"`
	SampleCount    int     `json:"sample_count"`
}
```

**Step 2: Extend SentinelData struct**

In the `SentinelData` struct (~line 536), add after the existing fields (before the aggregate rates section):

```go
	// Network security sentinels
	SynFlood    []SynFloodEntry    `json:"syn_flood,omitempty"`
	PortScans   []PortScanEntry    `json:"port_scans,omitempty"`
	DNSAnomaly  []DNSAnomalyEntry  `json:"dns_anomaly,omitempty"`
	FlowRates   []FlowRateEntry    `json:"flow_rates,omitempty"`
	OutboundTop []OutboundEntry    `json:"outbound_top,omitempty"`
```

**Step 3: Extend SecurityMetrics struct**

In the `SecurityMetrics` struct (~line 455), add after `Score`:

```go
	// Network security watchdog results
	TCPFlagAnomalies    []TCPFlagAnomaly     `json:"tcp_flag_anomalies,omitempty"`
	DNSTunnelIndicators []DNSTunnelIndicator  `json:"dns_tunnel_indicators,omitempty"`
	JA3Fingerprints     []JA3Entry           `json:"ja3_fingerprints,omitempty"`
	BeaconIndicators    []BeaconIndicator    `json:"beacon_indicators,omitempty"`
	ThreatScore         string               `json:"threat_score"`
	ActiveWatchdogs     []string             `json:"active_watchdogs,omitempty"`
```

**Step 4: Build and verify**

```bash
cd /home/rctop/whytop && go build ./...
```
Expected: Clean compile

**Step 5: Commit**

```bash
git add model/metrics.go
git commit -m "feat: add network security intelligence model types"
```

---

## Task 2: Sentinel BPF C Programs (5 new)

Create 5 BPF C programs for always-on network security monitoring.

**Files:**
- Create: `collector/ebpf/bpf/synflood.c`
- Create: `collector/ebpf/bpf/portscan.c`
- Create: `collector/ebpf/bpf/dnsmon.c`
- Create: `collector/ebpf/bpf/connrate.c`
- Create: `collector/ebpf/bpf/outbound.c`
- Reference: `collector/ebpf/bpf/kfreeskb.c` (template)

**Step 1: Create synflood.c**

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct syn_val {
	__u64 syn_count;
	__u64 synack_retrans;
	__u64 first_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct syn_val);
} syn_accum SEC(".maps");

// tcp_retransmit_synack tracepoint fires when kernel retransmits SYN-ACK
// (unanswered SYNs = half-open connections)
SEC("kprobe/tcp_retransmit_synack")
int handle_synack_retrans(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

	struct syn_val *val = bpf_map_lookup_elem(&syn_accum, &saddr);
	if (val) {
		__sync_fetch_and_add(&val->synack_retrans, 1);
	} else {
		struct syn_val new_val = {
			.syn_count = 0,
			.synack_retrans = 1,
			.first_ns = bpf_ktime_get_ns(),
		};
		bpf_map_update_elem(&syn_accum, &saddr, &new_val, BPF_NOEXIST);
	}
	return 0;
}

// tcp_conn_request fires on every inbound SYN
SEC("kprobe/tcp_conn_request")
int handle_syn_request(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM2(ctx);
	__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

	struct syn_val *val = bpf_map_lookup_elem(&syn_accum, &saddr);
	if (val) {
		__sync_fetch_and_add(&val->syn_count, 1);
	} else {
		struct syn_val new_val = {
			.syn_count = 1,
			.synack_retrans = 0,
			.first_ns = bpf_ktime_get_ns(),
		};
		bpf_map_update_elem(&syn_accum, &saddr, &new_val, BPF_NOEXIST);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 2: Create portscan.c**

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct scan_val {
	__u64 rst_count;
	__u64 port_bitmap;   // 64-bit bitmap for port diversity
	__u64 first_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2048);
	__type(key, __u32);
	__type(value, struct scan_val);
} scan_accum SEC(".maps");

// tcp_v4_send_reset fires when kernel sends RST (connection refused)
SEC("kprobe/tcp_v4_send_reset")
int handle_rst_sent(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	__u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	// Hash port into 64-bit bitmap bucket
	__u64 port_bit = 1ULL << (dport % 64);

	struct scan_val *val = bpf_map_lookup_elem(&scan_accum, &saddr);
	if (val) {
		__sync_fetch_and_add(&val->rst_count, 1);
		__sync_fetch_and_or(&val->port_bitmap, port_bit);
	} else {
		struct scan_val new_val = {
			.rst_count = 1,
			.port_bitmap = port_bit,
			.first_ns = bpf_ktime_get_ns(),
		};
		bpf_map_update_elem(&scan_accum, &saddr, &new_val, BPF_NOEXIST);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 3: Create dnsmon.c**

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct dns_val {
	__u64 query_count;
	__u64 total_query_bytes;
	__u64 total_resp_bytes;
	__u32 max_query_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct dns_val);
} dns_accum SEC(".maps");

// Track DNS queries via udp_sendmsg (outbound to port 53)
SEC("kprobe/udp_sendmsg")
int handle_udp_send(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	int len = (int)PT_REGS_PARM3(ctx);

	// Filter: only port 53 (DNS)
	__u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (dport != 53)
		return 0;

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == 0)
		return 0;

	struct dns_val *val = bpf_map_lookup_elem(&dns_accum, &pid);
	if (val) {
		__sync_fetch_and_add(&val->query_count, 1);
		__sync_fetch_and_add(&val->total_query_bytes, (__u64)len);
		if ((__u32)len > val->max_query_len)
			val->max_query_len = (__u32)len;
	} else {
		struct dns_val new_val = {
			.query_count = 1,
			.total_query_bytes = (__u64)len,
			.total_resp_bytes = 0,
			.max_query_len = (__u32)len,
		};
		bpf_map_update_elem(&dns_accum, &pid, &new_val, BPF_NOEXIST);
	}
	return 0;
}

// Track DNS responses via udp_recvmsg (inbound from port 53)
SEC("kprobe/udp_recvmsg")
int handle_udp_recv(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	int len = (int)PT_REGS_PARM3(ctx);

	__u16 sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (sport != 53)
		return 0;

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == 0)
		return 0;

	struct dns_val *val = bpf_map_lookup_elem(&dns_accum, &pid);
	if (val) {
		__sync_fetch_and_add(&val->total_resp_bytes, (__u64)len);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 4: Create connrate.c**

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct flow_key {
	__u32 pid;
	__u32 daddr;
};

struct flow_val {
	__u64 connect_count;
	__u64 close_count;
	__u64 first_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} flow_accum SEC(".maps");

// Per-PID unique destination counter
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} dest_count SEC(".maps");

// Track TCP state transitions for connect/close rates
struct inet_sock_set_state_args {
	unsigned long long unused;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

SEC("tracepoint/sock/inet_sock_set_state")
int handle_state_change(struct inet_sock_set_state_args *ctx)
{
	if (ctx->protocol != IPPROTO_TCP)
		return 0;
	if (ctx->family != AF_INET)
		return 0;

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == 0)
		return 0;

	__u32 daddr;
	bpf_probe_read_kernel(&daddr, sizeof(daddr), ctx->daddr);

	struct flow_key key = { .pid = pid, .daddr = daddr };

	// SYN_SENT(2) -> ESTABLISHED(1) = successful connect
	if (ctx->oldstate == 2 && ctx->newstate == 1) {
		struct flow_val *val = bpf_map_lookup_elem(&flow_accum, &key);
		if (val) {
			__sync_fetch_and_add(&val->connect_count, 1);
		} else {
			struct flow_val new_val = {
				.connect_count = 1,
				.close_count = 0,
				.first_ns = bpf_ktime_get_ns(),
			};
			bpf_map_update_elem(&flow_accum, &key, &new_val, BPF_NOEXIST);
		}
		// Increment unique destination counter
		__u64 *cnt = bpf_map_lookup_elem(&dest_count, &pid);
		if (cnt) {
			__sync_fetch_and_add(cnt, 1);
		} else {
			__u64 one = 1;
			bpf_map_update_elem(&dest_count, &pid, &one, BPF_NOEXIST);
		}
	}

	// ESTABLISHED(1) -> CLOSE_WAIT(8) or FIN_WAIT1(4) = connection closing
	if (ctx->oldstate == 1 && (ctx->newstate == 8 || ctx->newstate == 4)) {
		struct flow_val *val = bpf_map_lookup_elem(&flow_accum, &key);
		if (val) {
			__sync_fetch_and_add(&val->close_count, 1);
		}
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 5: Create outbound.c**

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct egress_key {
	__u32 pid;
	__u32 daddr;
};

struct egress_val {
	__u64 total_bytes;
	__u64 packet_count;
	__u64 last_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct egress_key);
	__type(value, struct egress_val);
} egress_accum SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int handle_tcp_send(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	int len = (int)PT_REGS_PARM3(ctx);

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == 0 || len <= 0)
		return 0;

	__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	if (daddr == 0)
		return 0;

	struct egress_key key = { .pid = pid, .daddr = daddr };

	struct egress_val *val = bpf_map_lookup_elem(&egress_accum, &key);
	if (val) {
		__sync_fetch_and_add(&val->total_bytes, (__u64)len);
		__sync_fetch_and_add(&val->packet_count, 1);
		val->last_ns = bpf_ktime_get_ns();
	} else {
		struct egress_val new_val = {
			.total_bytes = (__u64)len,
			.packet_count = 1,
			.last_ns = bpf_ktime_get_ns(),
		};
		bpf_map_update_elem(&egress_accum, &key, &new_val, BPF_NOEXIST);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 6: Build to check syntax**

```bash
cd /home/rctop/whytop && go build ./...
```
Expected: Still compiles (BPF C files are not compiled by go build, only by bpf2go)

**Step 7: Commit**

```bash
git add collector/ebpf/bpf/synflood.c collector/ebpf/bpf/portscan.c collector/ebpf/bpf/dnsmon.c collector/ebpf/bpf/connrate.c collector/ebpf/bpf/outbound.c
git commit -m "feat: add 5 sentinel BPF C programs for network security"
```

---

## Task 3: Watchdog BPF C Programs (4 new)

Create 4 BPF C programs for auto-triggered deep inspection.

**Files:**
- Create: `collector/ebpf/bpf/tcpflags.c`
- Create: `collector/ebpf/bpf/dnsdeep.c`
- Create: `collector/ebpf/bpf/tlsfinger.c`
- Create: `collector/ebpf/bpf/beacondetect.c`

**Step 1: Create tcpflags.c**

```c
// SPDX-License-Identifier: GPL-2.0
// TC ingress classifier for TCP flag anomaly detection
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP  0x0800
#define IPPROTO_TCP 6

// TCP flag bits
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

struct flags_key {
	__u32 saddr;
	__u8 flags;
	__u8 pad[3];
};

struct flags_val {
	__u64 count;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2048);
	__type(key, struct flags_key);
	__type(value, struct flags_val);
} flags_accum SEC(".maps");

SEC("tc")
int handle_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	// Parse ethernet header
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return 0; // TC_ACT_OK = pass through

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return 0;

	// Parse IP header
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return 0;

	if (ip->protocol != IPPROTO_TCP)
		return 0;

	// Parse TCP header
	struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
	if ((void *)(tcp + 1) > data_end)
		return 0;

	// Extract TCP flags byte (offset 13 in TCP header)
	__u8 flags = ((__u8 *)tcp)[13] & 0x3F; // mask to 6 standard flags

	// Only track anomalous flag combinations
	int anomalous = 0;
	// XMAS scan: FIN+PSH+URG
	if ((flags & (TH_FIN | TH_PUSH | TH_URG)) == (TH_FIN | TH_PUSH | TH_URG))
		anomalous = 1;
	// NULL scan: no flags
	if (flags == 0)
		anomalous = 1;
	// SYN+FIN: impossible in normal traffic
	if ((flags & (TH_SYN | TH_FIN)) == (TH_SYN | TH_FIN))
		anomalous = 1;
	// FIN without ACK: unusual
	if ((flags & (TH_FIN | TH_ACK)) == TH_FIN)
		anomalous = 1;

	if (!anomalous)
		return 0;

	struct flags_key key = { .saddr = ip->saddr, .flags = flags };

	struct flags_val *val = bpf_map_lookup_elem(&flags_accum, &key);
	if (val) {
		__sync_fetch_and_add(&val->count, 1);
	} else {
		struct flags_val new_val = { .count = 1 };
		bpf_map_update_elem(&flags_accum, &key, &new_val, BPF_NOEXIST);
	}

	return 0; // TC_ACT_OK = always pass through (monitoring only)
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 2: Create dnsdeep.c**

```c
// SPDX-License-Identifier: GPL-2.0
// TC classifier for DNS payload inspection (tunneling detection)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define IPPROTO_UDP 17
#define DNS_PORT    53

// DNS query types we track
#define DNS_TYPE_A     1
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_TXT   16
#define DNS_TYPE_MX    15
#define DNS_TYPE_CNAME 5

struct dns_deep_val {
	__u64 total_queries;
	__u64 txt_queries;
	__u64 total_query_bytes;
	__u32 max_name_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);   // source IP
	__type(value, struct dns_deep_val);
} dns_deep SEC(".maps");

SEC("tc")
int handle_dns_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return 0;
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return 0;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return 0;
	if (ip->protocol != IPPROTO_UDP)
		return 0;

	struct udphdr *udp = (void *)ip + (ip->ihl * 4);
	if ((void *)(udp + 1) > data_end)
		return 0;

	__u16 sport = bpf_ntohs(udp->source);
	__u16 dport = bpf_ntohs(udp->dest);

	// Only DNS traffic (port 53 either direction)
	if (sport != DNS_PORT && dport != DNS_PORT)
		return 0;

	// DNS header starts after UDP header
	void *dns_start = (void *)(udp + 1);
	if (dns_start + 12 > data_end) // DNS header is 12 bytes
		return 0;

	// Read query count from DNS header (bytes 4-5)
	__u16 qdcount = 0;
	bpf_probe_read_kernel(&qdcount, 2, dns_start + 4);
	qdcount = bpf_ntohs(qdcount);
	if (qdcount == 0)
		return 0;

	// Measure query name length (walk labels until 0)
	void *qname = dns_start + 12;
	__u32 name_len = 0;
	#pragma unroll
	for (int i = 0; i < 128; i++) {
		if (qname + 1 > data_end)
			break;
		__u8 label_len = 0;
		bpf_probe_read_kernel(&label_len, 1, qname);
		if (label_len == 0)
			break;
		name_len += label_len + 1;
		qname += label_len + 1;
	}

	// Read query type (2 bytes after the null-terminated name)
	__u16 qtype = 0;
	if (qname + 3 <= data_end)
		bpf_probe_read_kernel(&qtype, 2, qname + 1);
	qtype = bpf_ntohs(qtype);

	__u32 saddr = (dport == DNS_PORT) ? ip->saddr : ip->daddr;

	struct dns_deep_val *val = bpf_map_lookup_elem(&dns_deep, &saddr);
	if (val) {
		__sync_fetch_and_add(&val->total_queries, 1);
		if (qtype == DNS_TYPE_TXT)
			__sync_fetch_and_add(&val->txt_queries, 1);
		__sync_fetch_and_add(&val->total_query_bytes, (__u64)name_len);
		if (name_len > val->max_name_len)
			val->max_name_len = name_len;
	} else {
		struct dns_deep_val new_val = {
			.total_queries = 1,
			.txt_queries = (qtype == DNS_TYPE_TXT) ? 1 : 0,
			.total_query_bytes = name_len,
			.max_name_len = name_len,
		};
		bpf_map_update_elem(&dns_deep, &saddr, &new_val, BPF_NOEXIST);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 3: Create tlsfinger.c**

```c
// SPDX-License-Identifier: GPL-2.0
// TC classifier for TLS ClientHello JA3 fingerprinting
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6

// TLS constants
#define TLS_HANDSHAKE   22
#define TLS_CLIENT_HELLO 1

struct ja3_val {
	__u64 count;
	__u32 sample_saddr;
	__u32 sample_daddr;
	__u16 tls_version;
	__u16 cipher_count;
	__u16 ext_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 512);
	__type(key, __u32);   // simplified JA3 hash (FNV of version+ciphers+extensions)
	__type(value, struct ja3_val);
} ja3_accum SEC(".maps");

static __always_inline __u32 fnv1a(__u32 hash, __u8 byte)
{
	return (hash ^ byte) * 16777619;
}

SEC("tc")
int handle_tls_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return 0;
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return 0;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return 0;
	if (ip->protocol != IPPROTO_TCP)
		return 0;

	struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
	if ((void *)(tcp + 1) > data_end)
		return 0;

	// Only port 443 (HTTPS)
	__u16 dport = bpf_ntohs(tcp->dest);
	if (dport != 443)
		return 0;

	// TLS record starts after TCP header
	void *tls = (void *)tcp + (tcp->doff * 4);
	if (tls + 6 > data_end)
		return 0;

	// Check TLS record type (byte 0) = Handshake (22)
	__u8 content_type = 0;
	bpf_probe_read_kernel(&content_type, 1, tls);
	if (content_type != TLS_HANDSHAKE)
		return 0;

	// Check handshake type (byte 5) = ClientHello (1)
	__u8 handshake_type = 0;
	bpf_probe_read_kernel(&handshake_type, 1, tls + 5);
	if (handshake_type != TLS_CLIENT_HELLO)
		return 0;

	// Extract TLS version from ClientHello (bytes 9-10)
	__u16 tls_ver = 0;
	if (tls + 11 <= data_end)
		bpf_probe_read_kernel(&tls_ver, 2, tls + 9);

	// Build simplified JA3 hash from TLS version + session_id_len area
	// (full JA3 requires cipher/extension parsing which is complex in BPF)
	__u32 hash = 2166136261; // FNV offset basis
	hash = fnv1a(hash, (__u8)(tls_ver >> 8));
	hash = fnv1a(hash, (__u8)(tls_ver & 0xFF));

	// Read cipher suite list length at offset 43 + session_id_length
	__u8 session_id_len = 0;
	if (tls + 44 <= data_end)
		bpf_probe_read_kernel(&session_id_len, 1, tls + 43);

	void *cipher_start = tls + 44 + session_id_len;
	__u16 cipher_len = 0;
	if (cipher_start + 2 <= data_end)
		bpf_probe_read_kernel(&cipher_len, 2, cipher_start);
	cipher_len = bpf_ntohs(cipher_len);
	__u16 cipher_count = cipher_len / 2;

	// Hash first 8 cipher suite bytes (enough for fingerprint diversity)
	#pragma unroll
	for (int i = 0; i < 8; i++) {
		__u8 b = 0;
		if (cipher_start + 2 + i < data_end)
			bpf_probe_read_kernel(&b, 1, cipher_start + 2 + i);
		hash = fnv1a(hash, b);
	}

	struct ja3_val *val = bpf_map_lookup_elem(&ja3_accum, &hash);
	if (val) {
		__sync_fetch_and_add(&val->count, 1);
	} else {
		struct ja3_val new_val = {
			.count = 1,
			.sample_saddr = ip->saddr,
			.sample_daddr = ip->daddr,
			.tls_version = tls_ver,
			.cipher_count = cipher_count,
		};
		bpf_map_update_elem(&ja3_accum, &hash, &new_val, BPF_NOEXIST);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 4: Create beacondetect.c**

```c
// SPDX-License-Identifier: GPL-2.0
// Beacon detection via tcp_sendmsg inter-packet interval tracking
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct beacon_key {
	__u32 pid;
	__u32 daddr;
	__u16 dport;
	__u16 pad;
};

struct beacon_val {
	__u64 last_ns;
	__u64 interval_sum_ns;
	__u64 interval_count;
	__u64 min_interval_ns;
	__u64 max_interval_ns;
	__u64 send_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct beacon_key);
	__type(value, struct beacon_val);
} beacon_accum SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int handle_beacon_send(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == 0)
		return 0;

	__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	__u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (daddr == 0)
		return 0;

	struct beacon_key key = { .pid = pid, .daddr = daddr, .dport = dport };
	__u64 now = bpf_ktime_get_ns();

	struct beacon_val *val = bpf_map_lookup_elem(&beacon_accum, &key);
	if (val) {
		__sync_fetch_and_add(&val->send_count, 1);
		if (val->last_ns > 0) {
			__u64 interval = now - val->last_ns;
			// Only track reasonable intervals (100ms - 600s)
			if (interval > 100000000ULL && interval < 600000000000ULL) {
				__sync_fetch_and_add(&val->interval_sum_ns, interval);
				__sync_fetch_and_add(&val->interval_count, 1);
				if (interval < val->min_interval_ns || val->min_interval_ns == 0)
					val->min_interval_ns = interval;
				if (interval > val->max_interval_ns)
					val->max_interval_ns = interval;
			}
		}
		val->last_ns = now;
	} else {
		struct beacon_val new_val = {
			.last_ns = now,
			.interval_sum_ns = 0,
			.interval_count = 0,
			.min_interval_ns = 0,
			.max_interval_ns = 0,
			.send_count = 1,
		};
		bpf_map_update_elem(&beacon_accum, &key, &new_val, BPF_NOEXIST);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 5: Commit**

```bash
git add collector/ebpf/bpf/tcpflags.c collector/ebpf/bpf/dnsdeep.c collector/ebpf/bpf/tlsfinger.c collector/ebpf/bpf/beacondetect.c
git commit -m "feat: add 4 watchdog BPF C programs for deep network inspection"
```

---

## Task 4: BPF Code Generation & Go Wrappers

Add bpf2go directives, generate Go bindings, and write Go wrapper functions for all 9 probes.

**Files:**
- Modify: `collector/ebpf/gen.go` (add 9 new go:generate lines after line 25)
- Create: `collector/ebpf/synflood.go`
- Create: `collector/ebpf/portscan.go`
- Create: `collector/ebpf/dnsmon.go`
- Create: `collector/ebpf/connrate.go`
- Create: `collector/ebpf/outbound.go`
- Create: `collector/ebpf/tcpflags.go`
- Create: `collector/ebpf/dnsdeep.go`
- Create: `collector/ebpf/tlsfinger.go`
- Create: `collector/ebpf/beacondetect.go`

**Step 1: Update gen.go**

Add after existing directives (after line 25):

```go
// Network security sentinel probes
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 synflood bpf/synflood.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 portscan bpf/portscan.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 dnsmon bpf/dnsmon.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 connrate bpf/connrate.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 outbound bpf/outbound.c
// Network security watchdog probes
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 tcpflags bpf/tcpflags.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 dnsdeep bpf/dnsdeep.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 tlsfinger bpf/tlsfinger.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include" -target amd64 beacondetect bpf/beacondetect.c
```

**Step 2: Run code generation**

```bash
cd /home/rctop/whytop/collector/ebpf && GOPACKAGE=ebpf go generate
```

This generates `*_x86_bpfel.go` + `*_x86_bpfel.o` files for each probe.

**Step 3: Create Go wrappers for 5 sentinel probes**

Create `collector/ebpf/synflood.go`:
```go
package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type synfloodProbe struct {
	objs  synfloodObjects
	links []link.Link
}

func attachSynFlood() (*synfloodProbe, error) {
	var objs synfloodObjects
	if err := loadSynfloodObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load synflood: %w", err)
	}
	var links []link.Link

	l1, err := link.Kprobe("tcp_retransmit_synack", objs.HandleSynackRetrans, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach synack_retrans: %w", err)
	}
	links = append(links, l1)

	l2, err := link.Kprobe("tcp_conn_request", objs.HandleSynRequest, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach syn_request: %w", err)
	}
	links = append(links, l2)

	return &synfloodProbe{objs: objs, links: links}, nil
}

func (p *synfloodProbe) read() []model.SynFloodEntry {
	var results []model.SynFloodEntry
	var ip uint32
	var val synfloodSynVal

	iter := p.objs.SynAccum.Iterate()
	for iter.Next(&ip, &val) {
		if val.SynCount == 0 && val.SynackRetrans == 0 {
			continue
		}
		ratio := float64(0)
		if val.SynCount > 0 {
			ratio = float64(val.SynackRetrans) / float64(val.SynCount)
		}
		results = append(results, model.SynFloodEntry{
			SrcIP:         formatIPv4(ip),
			SynCount:      val.SynCount,
			SynAckRetrans: val.SynackRetrans,
			HalfOpenRatio: ratio,
		})
	}
	return results
}

func (p *synfloodProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

func formatIPv4(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}
```

Create `collector/ebpf/portscan.go`:
```go
package ebpf

import (
	"fmt"
	"math/bits"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type portscanProbe struct {
	objs  portscanObjects
	links []link.Link
}

func attachPortScan() (*portscanProbe, error) {
	var objs portscanObjects
	if err := loadPortscanObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load portscan: %w", err)
	}
	l, err := link.Kprobe("tcp_v4_send_reset", objs.HandleRstSent, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach portscan: %w", err)
	}
	return &portscanProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *portscanProbe) read() []model.PortScanEntry {
	var results []model.PortScanEntry
	var ip uint32
	var val portscanScanVal

	iter := p.objs.ScanAccum.Iterate()
	for iter.Next(&ip, &val) {
		if val.RstCount < 5 {
			continue
		}
		uniquePorts := bits.OnesCount64(val.PortBitmap)
		results = append(results, model.PortScanEntry{
			SrcIP:             formatIPv4(ip),
			RSTCount:          val.RstCount,
			UniquePortBuckets: uniquePorts,
		})
	}
	return results
}

func (p *portscanProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
```

Create `collector/ebpf/dnsmon.go`:
```go
package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type dnsmonProbe struct {
	objs  dnsmonObjects
	links []link.Link
}

func attachDNSMon() (*dnsmonProbe, error) {
	var objs dnsmonObjects
	if err := loadDnsmonObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load dnsmon: %w", err)
	}
	var links []link.Link

	l1, err := link.Kprobe("udp_sendmsg", objs.HandleUdpSend, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach udp_sendmsg: %w", err)
	}
	links = append(links, l1)

	l2, err := link.Kprobe("udp_recvmsg", objs.HandleUdpRecv, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach udp_recvmsg: %w", err)
	}
	links = append(links, l2)

	return &dnsmonProbe{objs: objs, links: links}, nil
}

func (p *dnsmonProbe) read() []model.DNSAnomalyEntry {
	var results []model.DNSAnomalyEntry
	var pid uint32
	var val dnsmonDnsVal

	iter := p.objs.DnsAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.QueryCount == 0 {
			continue
		}
		avgLen := 0
		if val.QueryCount > 0 {
			avgLen = int(val.TotalQueryBytes / val.QueryCount)
		}
		results = append(results, model.DNSAnomalyEntry{
			PID:            int(pid),
			Comm:           readComm(int(pid)),
			QueryCount:     val.QueryCount,
			AvgQueryLen:    avgLen,
			TotalRespBytes: val.TotalRespBytes,
		})
	}
	return results
}

func (p *dnsmonProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

func readComm(pid int) string {
	return readCommForPID(uint32(pid))
}
```

Create `collector/ebpf/connrate.go`:
```go
package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type connrateProbe struct {
	objs  connrateObjects
	links []link.Link
}

func attachConnRate() (*connrateProbe, error) {
	var objs connrateObjects
	if err := loadConnrateObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load connrate: %w", err)
	}
	l, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleStateChange, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach connrate: %w", err)
	}
	return &connrateProbe{objs: objs, links: []link.Link{l}}, nil
}

type connrateFlowKey struct {
	PID   uint32
	Daddr uint32
}

func (p *connrateProbe) read() ([]model.FlowRateEntry, map[uint32]int) {
	var results []model.FlowRateEntry
	var key connrateFlowKey
	var val connrateFlowVal

	// Track unique destinations per PID
	pidDests := make(map[uint32]map[uint32]bool)

	iter := p.objs.FlowAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.ConnectCount == 0 {
			continue
		}
		if pidDests[key.PID] == nil {
			pidDests[key.PID] = make(map[uint32]bool)
		}
		pidDests[key.PID][key.Daddr] = true

		results = append(results, model.FlowRateEntry{
			PID:          int(key.PID),
			Comm:         readComm(int(key.PID)),
			DstIP:        formatIPv4(key.Daddr),
			ConnectCount: val.ConnectCount,
			CloseCount:   val.CloseCount,
		})
	}

	// Build unique dest count map
	destCounts := make(map[uint32]int)
	for pid, dests := range pidDests {
		destCounts[pid] = len(dests)
	}

	return results, destCounts
}

func (p *connrateProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
```

Create `collector/ebpf/outbound.go`:
```go
package ebpf

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type outboundProbe struct {
	objs  outboundObjects
	links []link.Link
}

func attachOutbound() (*outboundProbe, error) {
	var objs outboundObjects
	if err := loadOutboundObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load outbound: %w", err)
	}
	l, err := link.Kprobe("tcp_sendmsg", objs.HandleTcpSend, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach outbound: %w", err)
	}
	return &outboundProbe{objs: objs, links: []link.Link{l}}, nil
}

type outboundEgressKey struct {
	PID   uint32
	Daddr uint32
}

func (p *outboundProbe) read() []model.OutboundEntry {
	var results []model.OutboundEntry
	var key outboundEgressKey
	var val outboundEgressVal

	iter := p.objs.EgressAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.TotalBytes == 0 {
			continue
		}
		results = append(results, model.OutboundEntry{
			PID:         int(key.PID),
			Comm:        readComm(int(key.PID)),
			DstIP:       formatIPv4(key.Daddr),
			TotalBytes:  val.TotalBytes,
			PacketCount: val.PacketCount,
		})
	}

	// Sort by total bytes descending, keep top 20
	sort.Slice(results, func(i, j int) bool {
		return results[i].TotalBytes > results[j].TotalBytes
	})
	if len(results) > 20 {
		results = results[:20]
	}

	return results
}

func (p *outboundProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
```

**Step 4: Create Go wrappers for 4 watchdog probes**

Create `collector/ebpf/tcpflags.go`:
```go
package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type tcpflagsProbe struct {
	objs  tcpflagsObjects
	links []link.Link
	iface string
}

// flagNames maps TCP flag byte to human-readable name
func flagName(flags uint8) string {
	switch {
	case flags == 0:
		return "NULL"
	case flags == 0x01:
		return "FIN"
	case flags == 0x03:
		return "SYN+FIN"
	case flags == 0x29:
		return "XMAS"
	case flags&0x03 == 0x03:
		return "SYN+FIN"
	default:
		return fmt.Sprintf("0x%02x", flags)
	}
}

type tcpflagsFlagsKey struct {
	Saddr uint32
	Flags uint8
	Pad   [3]uint8
}

func attachTCPFlags(ifname string) (*tcpflagsProbe, error) {
	var objs tcpflagsObjects
	if err := loadTcpflagsObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load tcpflags: %w", err)
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("interface %s: %w", ifname, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.HandleIngress,
		Attach:    1, // ingress
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tc ingress: %w", err)
	}

	return &tcpflagsProbe{objs: objs, links: []link.Link{l}, iface: ifname}, nil
}

func (p *tcpflagsProbe) read() []model.TCPFlagAnomaly {
	var results []model.TCPFlagAnomaly
	var key tcpflagsFlagsKey
	var val tcpflagsFlagsVal

	iter := p.objs.FlagsAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, model.TCPFlagAnomaly{
			SrcIP:     formatIPv4(key.Saddr),
			FlagCombo: flagName(key.Flags),
			Count:     val.Count,
		})
	}
	return results
}

func (p *tcpflagsProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
```

Create `collector/ebpf/dnsdeep.go`:
```go
package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type dnsdeepProbe struct {
	objs  dnsdeepObjects
	links []link.Link
}

func attachDNSDeep(ifname string) (*dnsdeepProbe, error) {
	var objs dnsdeepObjects
	if err := loadDnsdeepObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load dnsdeep: %w", err)
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("interface %s: %w", ifname, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.HandleDnsIngress,
		Attach:    1,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tc dnsdeep: %w", err)
	}

	return &dnsdeepProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *dnsdeepProbe) read() []model.DNSTunnelIndicator {
	var results []model.DNSTunnelIndicator
	var saddr uint32
	var val dnsdeepDnsDeepVal

	iter := p.objs.DnsDeep.Iterate()
	for iter.Next(&saddr, &val) {
		if val.TotalQueries == 0 {
			continue
		}
		txtRatio := float64(val.TxtQueries) / float64(val.TotalQueries)
		avgLen := int(0)
		if val.TotalQueries > 0 {
			avgLen = int(val.TotalQueryBytes / val.TotalQueries)
		}
		results = append(results, model.DNSTunnelIndicator{
			DomainHash:  fmt.Sprintf("%08x", saddr),
			TXTRatio:    txtRatio,
			AvgQueryLen: avgLen,
			QueryRate:   float64(val.TotalQueries),
		})
	}
	return results
}

func (p *dnsdeepProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
```

Create `collector/ebpf/tlsfinger.go`:
```go
package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type tlsfingerProbe struct {
	objs  tlsfingerObjects
	links []link.Link
}

// knownJA3 maps simplified JA3 hashes to known tool identifiers.
var knownJA3 = map[uint32]string{
	// These are placeholder hashes - real values populated at runtime
	// from observed traffic patterns
}

func attachTLSFinger(ifname string) (*tlsfingerProbe, error) {
	var objs tlsfingerObjects
	if err := loadTlsfingerObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load tlsfinger: %w", err)
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("interface %s: %w", ifname, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.HandleTlsIngress,
		Attach:    1,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tc tlsfinger: %w", err)
	}

	return &tlsfingerProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *tlsfingerProbe) read() []model.JA3Entry {
	var results []model.JA3Entry
	var hash uint32
	var val tlsfingerJa3Val

	iter := p.objs.Ja3Accum.Iterate()
	for iter.Next(&hash, &val) {
		if val.Count == 0 {
			continue
		}
		known := ""
		if name, ok := knownJA3[hash]; ok {
			known = name
		}
		results = append(results, model.JA3Entry{
			Hash:      fmt.Sprintf("%08x", hash),
			Count:     val.Count,
			SampleSrc: formatIPv4(val.SampleSaddr),
			SampleDst: formatIPv4(val.SampleDaddr),
			Known:     known,
		})
	}
	return results
}

func (p *tlsfingerProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
```

Create `collector/ebpf/beacondetect.go`:
```go
package ebpf

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type beacondetectProbe struct {
	objs  beacondetectObjects
	links []link.Link
}

func attachBeaconDetect() (*beacondetectProbe, error) {
	var objs beacondetectObjects
	if err := loadBeacondetectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load beacondetect: %w", err)
	}
	l, err := link.Kprobe("tcp_sendmsg", objs.HandleBeaconSend, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach beacondetect: %w", err)
	}
	return &beacondetectProbe{objs: objs, links: []link.Link{l}}, nil
}

type beacondetectBeaconKey struct {
	PID   uint32
	Daddr uint32
	Dport uint16
	Pad   uint16
}

func (p *beacondetectProbe) read() []model.BeaconIndicator {
	var results []model.BeaconIndicator
	var key beacondetectBeaconKey
	var val beacondetectBeaconVal

	iter := p.objs.BeaconAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.IntervalCount < 5 {
			continue // need enough samples
		}
		avgNs := val.IntervalSumNs / val.IntervalCount
		avgSec := float64(avgNs) / 1e9
		jitter := float64(0)
		if avgNs > 0 {
			jitter = float64(val.MaxIntervalNs-val.MinIntervalNs) / float64(avgNs)
		}

		results = append(results, model.BeaconIndicator{
			PID:            int(key.PID),
			Comm:           readComm(int(key.PID)),
			DstIP:          formatIPv4(key.Daddr),
			DstPort:        key.Dport,
			AvgIntervalSec: avgSec,
			Jitter:         jitter,
			SampleCount:    int(val.IntervalCount),
		})
	}

	// Sort by jitter ascending (lowest jitter = most suspicious)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Jitter < results[j].Jitter
	})

	if len(results) > 10 {
		results = results[:10]
	}
	return results
}

func (p *beacondetectProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
```

**Step 5: Build and verify**

```bash
cd /home/rctop/whytop && go build ./...
```

**Step 6: Commit**

```bash
git add collector/ebpf/gen.go collector/ebpf/synflood.go collector/ebpf/portscan.go collector/ebpf/dnsmon.go collector/ebpf/connrate.go collector/ebpf/outbound.go collector/ebpf/tcpflags.go collector/ebpf/dnsdeep.go collector/ebpf/tlsfinger.go collector/ebpf/beacondetect.go collector/ebpf/*_x86_bpfel.*
git commit -m "feat: add Go wrappers and generated bindings for 9 security probes"
```

---

## Task 5: Sentinel Manager Integration

Register the 5 new sentinel probes in the SentinelManager.

**Files:**
- Modify: `collector/ebpf/sentinel.go` (add probe fields, attach calls, read calls)
- Modify: `collector/ebpf/detect.go` (add sentinel checks)

**Step 1: Add probe fields to SentinelManager struct**

In `sentinel.go`, add to the SentinelManager struct (after `ptracedetect` field, ~line 30):

```go
	// Network security sentinels
	synflood    *synfloodProbe
	portscan    *portscanProbe
	dnsmon      *dnsmonProbe
	connrate    *connrateProbe
	outbound    *outboundProbe
```

Add delta tracking maps (after existing prev maps):

```go
	prevSynFlood  map[uint32]synfloodSynVal
	prevPortScans map[uint32]portscanScanVal
	prevDNS       map[uint32]dnsmonDnsVal
	prevOutbound  map[outboundEgressKey]outboundEgressVal
```

Update `totalCount` from 11 to 16 (~line 62).

**Step 2: Add attachment calls in attach()**

In the `attach()` function, after the `ptracedetect` attachment block (~line 529), add:

```go
	if p, err := attachSynFlood(); err != nil {
		errs = append(errs, fmt.Sprintf("synflood: %v", err))
	} else {
		s.synflood = p
		s.attachedCount++
	}

	if p, err := attachPortScan(); err != nil {
		errs = append(errs, fmt.Sprintf("portscan: %v", err))
	} else {
		s.portscan = p
		s.attachedCount++
	}

	if p, err := attachDNSMon(); err != nil {
		errs = append(errs, fmt.Sprintf("dnsmon: %v", err))
	} else {
		s.dnsmon = p
		s.attachedCount++
	}

	if p, err := attachConnRate(); err != nil {
		errs = append(errs, fmt.Sprintf("connrate: %v", err))
	} else {
		s.connrate = p
		s.attachedCount++
	}

	if p, err := attachOutbound(); err != nil {
		errs = append(errs, fmt.Sprintf("outbound: %v", err))
	} else {
		s.outbound = p
		s.attachedCount++
	}
```

**Step 3: Add read calls in Collect()**

In the `Collect()` function, after existing sentinel data population, add reading for each new probe with delta computation (same pattern as existing probes):

```go
	// Read network security sentinels
	if s.synflood != nil {
		sd.SynFlood = s.synflood.read()
		// Compute rates from deltas
		for i := range sd.SynFlood {
			// Rate = total count / interval
			sd.SynFlood[i].Rate = float64(sd.SynFlood[i].SynCount) / float64(s.intervalSec)
		}
	}
	if s.portscan != nil {
		sd.PortScans = s.portscan.read()
		for i := range sd.PortScans {
			sd.PortScans[i].Rate = float64(sd.PortScans[i].RSTCount) / float64(s.intervalSec)
		}
	}
	if s.dnsmon != nil {
		sd.DNSAnomaly = s.dnsmon.read()
		for i := range sd.DNSAnomaly {
			sd.DNSAnomaly[i].QueriesPerSec = float64(sd.DNSAnomaly[i].QueryCount) / float64(s.intervalSec)
		}
	}
	if s.connrate != nil {
		flows, destCounts := s.connrate.read()
		for i := range flows {
			flows[i].UniqueDestCount = destCounts[uint32(flows[i].PID)]
			flows[i].Rate = float64(flows[i].ConnectCount) / float64(s.intervalSec)
		}
		sd.FlowRates = flows
	}
	if s.outbound != nil {
		sd.OutboundTop = s.outbound.read()
		for i := range sd.OutboundTop {
			sd.OutboundTop[i].BytesPerSec = float64(sd.OutboundTop[i].TotalBytes) / float64(s.intervalSec)
		}
	}
```

**Step 4: Add close calls**

In the `Close()` method, add cleanup for each new probe:

```go
	if s.synflood != nil { s.synflood.close() }
	if s.portscan != nil { s.portscan.close() }
	if s.dnsmon != nil { s.dnsmon.close() }
	if s.connrate != nil { s.connrate.close() }
	if s.outbound != nil { s.outbound.close() }
```

**Step 5: Update detect.go**

Add to the `sentinelChecks` map:

```go
	"synflood":  {}, // kprobe
	"portscan":  {}, // kprobe
	"dnsmon":    {}, // kprobe
	"connrate":  {"sock/inet_sock_set_state"},
	"outbound":  {}, // kprobe
```

**Step 6: Build and verify**

```bash
cd /home/rctop/whytop && go build ./...
```

**Step 7: Commit**

```bash
git add collector/ebpf/sentinel.go collector/ebpf/detect.go
git commit -m "feat: register 5 network security sentinel probes"
```

---

## Task 6: Watchdog Trigger Integration

Add the "Security Threat" watchdog domain to auto-trigger deep inspection probes.

**Files:**
- Modify: `collector/ebpf/runner.go` (or `watchdog.go` — wherever watchdog domain triggering lives)
- May need a new file: `collector/ebpf/secwatchdog.go` for security-specific watchdog orchestration

**Step 1: Create security watchdog manager**

Create `collector/ebpf/secwatchdog.go`:

```go
package ebpf

import (
	"context"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// SecWatchdog manages auto-triggered security deep-inspection probes.
type SecWatchdog struct {
	mu sync.Mutex

	// Active probes
	tcpflags     *tcpflagsProbe
	dnsdeep      *dnsdeepProbe
	tlsfinger    *tlsfingerProbe
	beacondetect *beacondetectProbe

	// Expiry timers
	tcpflagsExpiry     time.Time
	dnsdeepExpiry      time.Time
	tlsfingerExpiry    time.Time
	beacondetectExpiry time.Time

	// Primary interface for TC probes
	iface string
}

func NewSecWatchdog(iface string) *SecWatchdog {
	return &SecWatchdog{iface: iface}
}

// TriggerFromEvidence checks fired security evidence and activates relevant probes.
func (w *SecWatchdog) TriggerFromEvidence(evidence []model.Evidence) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()

	for _, ev := range evidence {
		if ev.Strength < 0.5 {
			continue
		}
		switch ev.ID {
		case "sec.portscan":
			if w.tcpflags == nil || now.After(w.tcpflagsExpiry) {
				w.activateTCPFlags(now)
			}
		case "sec.dns.anomaly":
			if w.dnsdeep == nil || now.After(w.dnsdeepExpiry) {
				w.activateDNSDeep(now)
			}
		case "sec.outbound.exfil", "sec.beacon":
			if w.tlsfinger == nil || now.After(w.tlsfingerExpiry) {
				w.activateTLSFinger(now)
			}
			if w.beacondetect == nil || now.After(w.beacondetectExpiry) {
				w.activateBeaconDetect(now)
			}
		}
	}
}

func (w *SecWatchdog) activateTCPFlags(now time.Time) {
	if w.tcpflags != nil {
		w.tcpflags.close()
	}
	p, err := attachTCPFlags(w.iface)
	if err != nil {
		return
	}
	w.tcpflags = p
	w.tcpflagsExpiry = now.Add(60 * time.Second)
}

func (w *SecWatchdog) activateDNSDeep(now time.Time) {
	if w.dnsdeep != nil {
		w.dnsdeep.close()
	}
	p, err := attachDNSDeep(w.iface)
	if err != nil {
		return
	}
	w.dnsdeep = p
	w.dnsdeepExpiry = now.Add(60 * time.Second)
}

func (w *SecWatchdog) activateTLSFinger(now time.Time) {
	if w.tlsfinger != nil {
		w.tlsfinger.close()
	}
	p, err := attachTLSFinger(w.iface)
	if err != nil {
		return
	}
	w.tlsfinger = p
	w.tlsfingerExpiry = now.Add(60 * time.Second)
}

func (w *SecWatchdog) activateBeaconDetect(now time.Time) {
	if w.beacondetect != nil {
		w.beacondetect.close()
	}
	p, err := attachBeaconDetect()
	if err != nil {
		return
	}
	w.beacondetect = p
	w.beacondetectExpiry = now.Add(120 * time.Second)
}

// Collect reads data from active watchdog probes and expires old ones.
func (w *SecWatchdog) Collect(sec *model.SecurityMetrics) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()

	sec.ActiveWatchdogs = nil

	if w.tcpflags != nil {
		if now.After(w.tcpflagsExpiry) {
			w.tcpflags.close()
			w.tcpflags = nil
		} else {
			sec.TCPFlagAnomalies = w.tcpflags.read()
			sec.ActiveWatchdogs = append(sec.ActiveWatchdogs, "tcpflags")
		}
	}
	if w.dnsdeep != nil {
		if now.After(w.dnsdeepExpiry) {
			w.dnsdeep.close()
			w.dnsdeep = nil
		} else {
			sec.DNSTunnelIndicators = w.dnsdeep.read()
			sec.ActiveWatchdogs = append(sec.ActiveWatchdogs, "dnsdeep")
		}
	}
	if w.tlsfinger != nil {
		if now.After(w.tlsfingerExpiry) {
			w.tlsfinger.close()
			w.tlsfinger = nil
		} else {
			sec.JA3Fingerprints = w.tlsfinger.read()
			sec.ActiveWatchdogs = append(sec.ActiveWatchdogs, "tlsfinger")
		}
	}
	if w.beacondetect != nil {
		if now.After(w.beacondetectExpiry) {
			w.beacondetect.close()
			w.beacondetect = nil
		} else {
			sec.BeaconIndicators = w.beacondetect.read()
			sec.ActiveWatchdogs = append(sec.ActiveWatchdogs, "beacondetect")
		}
	}

	// Set threat score
	if len(sec.ActiveWatchdogs) > 0 {
		sec.ThreatScore = "THREAT"
	} else if len(sec.TCPFlagAnomalies) > 0 || len(sec.DNSTunnelIndicators) > 0 {
		sec.ThreatScore = "ANOMALY"
	} else {
		sec.ThreatScore = "CLEAR"
	}
}

// Close shuts down all active watchdog probes.
func (w *SecWatchdog) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.tcpflags != nil { w.tcpflags.close(); w.tcpflags = nil }
	if w.dnsdeep != nil { w.dnsdeep.close(); w.dnsdeep = nil }
	if w.tlsfinger != nil { w.tlsfinger.close(); w.tlsfinger = nil }
	if w.beacondetect != nil { w.beacondetect.close(); w.beacondetect = nil }
}
```

**Step 2: Integrate SecWatchdog into engine**

In `engine/engine.go`, add a SecWatchdog field to the Engine struct. Initialize it in NewEngine(). After each RCA analysis cycle, call `secWatchdog.TriggerFromEvidence(result.RCA[networkDomainIndex].EvidenceV2)` and `secWatchdog.Collect(&snap.Global.Security)`.

**Step 3: Build and verify**

```bash
cd /home/rctop/whytop && go build ./...
```

**Step 4: Commit**

```bash
git add collector/ebpf/secwatchdog.go engine/engine.go
git commit -m "feat: add security watchdog auto-trigger for deep inspection probes"
```

---

## Task 7: RCA Evidence & Engine Integration

Add 8 new security evidence signals to the RCA engine.

**Files:**
- Modify: `engine/rca.go` (add security evidence in analyzeNetwork or new analyzeSecurity function)
- Modify: `engine/evidence.go` (add weight categories)
- Modify: `engine/patterns.go` (add 6 attack patterns)
- Modify: `engine/causal.go` (add 8 causal rules)
- Modify: `engine/temporal.go` (add cross-signal pairs + labels)
- Modify: `engine/narrative.go` (add 8 narrative templates)

**Step 1: Add evidence weight categories**

In `engine/evidence.go`, add to the `evidenceWeightCategory` map:

```go
	// Security
	"sec.synflood":       "psi",
	"sec.portscan":       "latency",
	"sec.dns.anomaly":    "queue",
	"sec.dns.tunnel":     "psi",
	"sec.outbound.exfil": "latency",
	"sec.lateral":        "queue",
	"sec.beacon":         "psi",
	"sec.tcp.flags":      "secondary",
```

**Step 2: Add security evidence to analyzeNetwork**

In `engine/rca.go`, in the `analyzeNetwork()` function, after the existing CLOSE_WAIT evidence block (~line 887), add:

```go
	// --- Network security evidence (BPF sentinel) ---
	if curr.Global.Sentinel.Active {
		// SYN flood detection
		maxSynRate := float64(0)
		for _, sf := range curr.Global.Sentinel.SynFlood {
			if sf.Rate > maxSynRate {
				maxSynRate = sf.Rate
			}
		}
		if maxSynRate > 0 {
			ws, cs := threshold("sec.synflood", 100, 1000)
			ev = append(ev, emitEvidence("sec.synflood", model.DomainNetwork,
				maxSynRate, ws, cs, true, 0.9,
				fmt.Sprintf("SYN flood: %.0f SYN/s from single source", maxSynRate), "3s",
				nil, nil))
		}

		// Port scan detection
		maxPortBuckets := 0
		for _, ps := range curr.Global.Sentinel.PortScans {
			if ps.UniquePortBuckets > maxPortBuckets {
				maxPortBuckets = ps.UniquePortBuckets
			}
		}
		if maxPortBuckets > 0 {
			ws, cs := threshold("sec.portscan", 10, 30)
			ev = append(ev, emitEvidence("sec.portscan", model.DomainNetwork,
				float64(maxPortBuckets), ws, cs, true, 0.85,
				fmt.Sprintf("Port scan: %d unique port groups from single source", maxPortBuckets), "3s",
				nil, nil))
		}

		// DNS anomaly detection
		maxDNSRate := float64(0)
		for _, dns := range curr.Global.Sentinel.DNSAnomaly {
			if dns.QueriesPerSec > maxDNSRate {
				maxDNSRate = dns.QueriesPerSec
			}
		}
		if maxDNSRate > 0 {
			ws, cs := threshold("sec.dns.anomaly", 50, 200)
			ev = append(ev, emitEvidence("sec.dns.anomaly", model.DomainNetwork,
				maxDNSRate, ws, cs, true, 0.8,
				fmt.Sprintf("DNS anomaly: %.0f queries/s", maxDNSRate), "3s",
				nil, nil))
		}

		// DNS tunneling (from watchdog results)
		maxTXTRatio := float64(0)
		for _, dt := range curr.Global.Security.DNSTunnelIndicators {
			if dt.TXTRatio > maxTXTRatio {
				maxTXTRatio = dt.TXTRatio
			}
		}
		if maxTXTRatio > 0 {
			ws, cs := threshold("sec.dns.tunnel", 0.3, 0.7)
			ev = append(ev, emitEvidence("sec.dns.tunnel", model.DomainNetwork,
				maxTXTRatio, ws, cs, true, 0.85,
				fmt.Sprintf("DNS tunneling: %.0f%% TXT queries", maxTXTRatio*100), "60s",
				nil, nil))
		}

		// Data exfiltration detection
		maxEgressMBHr := float64(0)
		for _, ob := range curr.Global.Sentinel.OutboundTop {
			mbhr := ob.BytesPerSec * 3600 / (1024 * 1024)
			if mbhr > maxEgressMBHr {
				maxEgressMBHr = mbhr
			}
		}
		if maxEgressMBHr > 0 {
			ws, cs := threshold("sec.outbound.exfil", 50, 500)
			ev = append(ev, emitEvidence("sec.outbound.exfil", model.DomainNetwork,
				maxEgressMBHr, ws, cs, true, 0.8,
				fmt.Sprintf("Outbound data: %.0f MB/hr to single destination", maxEgressMBHr), "3s",
				nil, nil))
		}

		// Lateral movement detection
		maxDests := 0
		for _, fr := range curr.Global.Sentinel.FlowRates {
			if fr.UniqueDestCount > maxDests {
				maxDests = fr.UniqueDestCount
			}
		}
		if maxDests > 0 {
			ws, cs := threshold("sec.lateral", 20, 50)
			ev = append(ev, emitEvidence("sec.lateral", model.DomainNetwork,
				float64(maxDests), ws, cs, true, 0.75,
				fmt.Sprintf("Lateral movement: %d unique destinations from single PID", maxDests), "3s",
				nil, nil))
		}

		// C2 beacon detection (from watchdog results)
		minJitter := float64(1.0)
		for _, bi := range curr.Global.Security.BeaconIndicators {
			if bi.Jitter < minJitter {
				minJitter = bi.Jitter
			}
		}
		if minJitter < 1.0 && len(curr.Global.Security.BeaconIndicators) > 0 {
			// Invert: lower jitter = more suspicious = higher strength
			ws, cs := threshold("sec.beacon", 0.2, 0)
			ev = append(ev, emitEvidence("sec.beacon", model.DomainNetwork,
				1.0-minJitter, 1.0-ws, 1.0-cs, true, 0.85,
				fmt.Sprintf("C2 beacon: %.1f%% jitter (regular intervals)", minJitter*100), "120s",
				nil, nil))
		}

		// TCP flag anomalies (from watchdog results)
		totalFlagCount := uint64(0)
		for _, fa := range curr.Global.Security.TCPFlagAnomalies {
			totalFlagCount += fa.Count
		}
		if totalFlagCount > 0 {
			ws, cs := threshold("sec.tcp.flags", 1, 10)
			ev = append(ev, emitEvidence("sec.tcp.flags", model.DomainNetwork,
				float64(totalFlagCount), ws, cs, true, 0.9,
				fmt.Sprintf("TCP flag anomalies: %d suspicious packets", totalFlagCount), "60s",
				nil, nil))
		}
	}
```

**Step 3: Add patterns**

In `engine/patterns.go`, add 6 new patterns to the `patternLibrary` slice (insert before the existing network patterns at priority 60, since these are higher priority):

```go
	{
		Name: "DDoS SYN Flood",
		Conditions: []PatternCondition{
			{ID: "sec.synflood"},
			{ID: "net.conntrack.growth"},
		},
		MinMatch: 1, Priority: 70, MinStr: 0.4,
		Narrative: "DDoS SYN flood — half-open connections exhausting resources",
	},
	{
		Name: "Port Scan Attack",
		Conditions: []PatternCondition{
			{ID: "sec.portscan"},
			{ID: "sec.tcp.flags"},
		},
		MinMatch: 1, Priority: 68, MinStr: 0.4,
		Narrative: "Port scan attack — reconnaissance activity detected",
	},
	{
		Name: "C2 Beacon Active",
		Conditions: []PatternCondition{
			{ID: "sec.beacon"},
			{ID: "sec.outbound.exfil"},
		},
		MinMatch: 1, Priority: 66, MinStr: 0.4,
		Narrative: "Command & control beacon — periodic callbacks to external host",
	},
	{
		Name: "DNS Tunneling",
		Conditions: []PatternCondition{
			{ID: "sec.dns.tunnel"},
			{ID: "sec.dns.anomaly"},
		},
		MinMatch: 2, Priority: 64, MinStr: 0.4,
		Narrative: "DNS tunneling — data exfiltration through DNS query encoding",
	},
	{
		Name: "Data Exfiltration",
		Conditions: []PatternCondition{
			{ID: "sec.outbound.exfil"},
			{ID: "sec.lateral"},
		},
		MinMatch: 1, Priority: 62, MinStr: 0.4,
		Narrative: "Data exfiltration — large outbound transfers to external destinations",
	},
	{
		Name: "Network Reconnaissance",
		Conditions: []PatternCondition{
			{ID: "sec.portscan"},
			{ID: "net.tcp.retrans"},
		},
		MinMatch: 1, Priority: 58, MinStr: 0.3,
		Narrative: "Network reconnaissance — scanning activity causing retransmits",
	},
```

**Step 4: Add causal rules**

In `engine/causal.go`, add after the existing network rules:

```go
	// Security domain
	{"sec.synflood", "net.conntrack.growth", "synflood→ctgrowth", 0.9},
	{"sec.synflood", "net.drops", "synflood→drops", 0.8},
	{"sec.portscan", "net.sentinel.resets", "portscan→resets", 0.85},
	{"sec.dns.anomaly", "sec.dns.tunnel", "dnsanomaly→tunnel", 0.7},
	{"sec.lateral", "sec.outbound.exfil", "lateral→exfil", 0.75},
	{"sec.beacon", "sec.outbound.exfil", "beacon→exfil", 0.6},
	{"sec.tcp.flags", "sec.portscan", "tcpflags→portscan", 0.8},
	{"sec.synflood", "cpu.busy", "synflood→cpubusy", 0.5},
```

**Step 5: Add temporal labels and cross-signal pairs**

In `engine/temporal.go`, add to the `shortLabel` map:

```go
	"sec.synflood":       "SYN flood",
	"sec.portscan":       "port scan",
	"sec.dns.anomaly":    "DNS anomaly",
	"sec.dns.tunnel":     "DNS tunnel",
	"sec.outbound.exfil": "data exfil",
	"sec.lateral":        "lateral mvmt",
	"sec.beacon":         "C2 beacon",
	"sec.tcp.flags":      "TCP flags",
```

Add to `predefinedPairs`:

```go
	{"sec.synflood", "net.conntrack.growth", "SYN flood driving conntrack table growth"},
	{"sec.portscan", "net.sentinel.resets", "Port scanning causing TCP RST responses"},
	{"sec.dns.anomaly", "sec.dns.tunnel", "Elevated DNS leading to tunneling detection"},
	{"sec.beacon", "sec.outbound.exfil", "C2 beacon associated with data exfiltration"},
```

**Step 6: Add narrative templates**

In `engine/narrative.go`, add to the `narrativeTemplates` slice (before the existing network templates):

```go
	// Security threats
	{ids: []string{"sec.synflood", "net.drops"}, text: "DDoS SYN flood — half-open connections exhausting resources and causing drops"},
	{ids: []string{"sec.synflood"}, text: "SYN flood detected — high rate of unanswered SYN packets from single source"},
	{ids: []string{"sec.portscan", "sec.tcp.flags"}, text: "Port scan with evasion — anomalous TCP flags indicate stealth scanning"},
	{ids: []string{"sec.portscan"}, text: "Port scan detected — reconnaissance probing multiple ports"},
	{ids: []string{"sec.dns.tunnel"}, text: "DNS tunneling — data exfiltration encoded in DNS queries"},
	{ids: []string{"sec.beacon"}, text: "C2 beacon — periodic fixed-interval callbacks to external host"},
	{ids: []string{"sec.outbound.exfil"}, text: "Data exfiltration — large outbound data volume to single destination"},
	{ids: []string{"sec.lateral"}, text: "Lateral movement — process connecting to many internal hosts"},
```

**Step 7: Build and verify**

```bash
cd /home/rctop/whytop && go build ./...
```

**Step 8: Commit**

```bash
git add engine/rca.go engine/evidence.go engine/patterns.go engine/causal.go engine/temporal.go engine/narrative.go
git commit -m "feat: add 8 security evidence signals, 6 attack patterns, 8 causal rules"
```

---

## Task 8: Security Page UI Enhancement

Add 5 new collapsible sections to the Security page.

**Files:**
- Modify: `ui/page_security.go` (add section constants, collapsible section rendering, 5 new content sections)
- Modify: `ui/app.go` (add model fields for section state, key handling)
- Modify: `ui/explain.go` (add security glossary entries)

**Step 1: Add section constants and model fields**

In `ui/app.go`, add to the model struct:

```go
	// Security page collapsible sections
	secSectionCursor   int
	secSectionExpanded [14]bool
	secManualOverride  bool
```

Add key handling in the security page key handler (same pattern as network page):

```go
case "j":
	if m.currentPage == pageSecurityIdx {
		m.secSectionCursor = (m.secSectionCursor + 1) % 14
	}
case "k":
	if m.currentPage == pageSecurityIdx {
		m.secSectionCursor = (m.secSectionCursor + 13) % 14
	}
```

And Enter, A, C key handling following the same pattern as the network page collapsible sections.

**Step 2: Add section constants to page_security.go**

At the top of `ui/page_security.go`, add:

```go
const (
	secSecAuth          = 0
	secSecPorts         = 1
	secSecSUID          = 2
	secSecExec          = 3
	secSecPtrace        = 4
	secSecReverseShell  = 5
	secSecFileless      = 6
	secSecModLoads      = 7
	secSecSessions      = 8
	secSecThreatOverview = 9
	secSecAttacks       = 10
	secSecDNS           = 11
	secSecFlows         = 12
	secSecTLS           = 13
	secSecCount         = 14
)
```

**Step 3: Add rendering for 5 new sections**

Add render functions following the existing pattern with `renderSecSectionHeader()` (same as `renderNetSectionHeader()` pattern):

`renderSecThreatOverview()` — threat status badge, primary/secondary threats, active watchdog list with remaining time.

`renderSecAttacks()` — SYN flood table (source IP, SYN/s, half-open%, duration), port scan table (source IP, RSTs, port buckets, scan type), TCP flag anomaly table.

`renderSecDNS()` — per-PID DNS stats (PID, comm, queries/s, avg len, TXT%, verdict). When dnsdeep active: tunneling indicators.

`renderSecFlows()` — outbound volume table (PID, comm, dest IP, MB/hr, pkts/s, EXFIL flag), lateral movement (PID, comm, unique dests, rate, LATERAL flag), beacon detection (PID, comm, dest, interval, jitter, C2 flag).

`renderSecTLS()` — JA3 fingerprint table (hash, count, sample src, known match). Only populated when tlsfinger watchdog active.

Each section uses the collapsible header pattern with auto-expand on anomaly detection.

**Step 4: Add explain panel glossary entries**

In `ui/explain.go`, add to the security page glossary:

```go
	{"SYN Flood", "Massive SYN packet rate overwhelming connection table"},
	{"Port Scan", "Systematic probing of ports to find running services"},
	{"DNS Tunneling", "Data exfiltration encoded in DNS query names"},
	{"C2 Beacon", "Malware callback to command server at regular intervals"},
	{"JA3 Fingerprint", "TLS client fingerprint from ClientHello parameters"},
	{"Data Exfiltration", "Unauthorized transfer of data to external destination"},
	{"Lateral Movement", "Attacker moving between internal hosts after compromise"},
	{"TCP Flag Anomaly", "Unusual TCP flag combinations (XMAS, NULL scan, etc.)"},
	{"Watchdog Probe", "Auto-triggered deep inspection probe (60-120s burst)"},
	{"Half-Open Ratio", "% of SYN packets without completed handshake"},
	{"TXT Ratio", "% of DNS queries using TXT type (high = tunneling)"},
	{"Beacon Jitter", "Regularity of callback intervals (low jitter = suspicious)"},
```

**Step 5: Build and verify**

```bash
cd /home/rctop/whytop && go build ./...
```

**Step 6: Commit**

```bash
git add ui/page_security.go ui/app.go ui/explain.go
git commit -m "feat: add 5 collapsible security intelligence sections to Security page"
```

---

## Task 9: Version Bump, Build & Deploy

**Files:**
- Modify: `cmd/root.go` (version 0.20.2 → 0.21.0)
- Modify: `README.md` (version references)
- Create: `packaging/xtop_0.21.0-1_amd64/DEBIAN/control`

**Step 1: Update version**

In `cmd/root.go`, change `Version = "0.20.2"` to `Version = "0.21.0"`.

**Step 2: Update README**

Replace all `0.20.2` references with `0.21.0` in install commands and badge.

**Step 3: Create packaging control**

```bash
mkdir -p packaging/xtop_0.21.0-1_amd64/DEBIAN
```

Create `packaging/xtop_0.21.0-1_amd64/DEBIAN/control`:
```
Package: xtop
Version: 0.21.0
Architecture: amd64
Maintainer: ftahirops
Description: xtop - AI-powered system observability TUI
 Real-time root cause analysis with eBPF probes
```

**Step 4: Build binary and deb**

```bash
cd /home/rctop/whytop
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.21.0" -o xtop .
mkdir -p packaging/xtop_0.21.0-1_amd64/usr/local/bin
cp xtop packaging/xtop_0.21.0-1_amd64/usr/local/bin/
dpkg-deb --build packaging/xtop_0.21.0-1_amd64
```

**Step 5: Deploy locally**

```bash
sudo rm -f /usr/local/bin/xtop && sudo cp xtop /usr/local/bin/xtop
```

**Step 6: Verify**

```bash
sudo xtop --version
# Expected: xtop version 0.21.0
```

Run `sudo xtop`, press `L` for Security page, verify new sections appear.

**Step 7: Commit and release**

```bash
git add cmd/root.go README.md packaging/xtop_0.21.0-1_amd64/
git commit -m "release: v0.21.0 — eBPF network security intelligence"
git push origin main
gh release create v0.21.0 packaging/xtop_0.21.0-1_amd64.deb --title "v0.21.0 — eBPF Network Security Intelligence" --notes "..."
```

---

## Implementation Order Summary

| Task | Description | Dependencies |
|------|-------------|-------------|
| 1 | Model types | None |
| 2 | BPF C sentinel programs | None |
| 3 | BPF C watchdog programs | None |
| 4 | Code gen + Go wrappers | Tasks 1, 2, 3 |
| 5 | Sentinel manager integration | Task 4 |
| 6 | Watchdog trigger integration | Tasks 4, 5 |
| 7 | RCA evidence + patterns + causal | Tasks 1, 5 |
| 8 | Security page UI | Tasks 1, 5, 6, 7 |
| 9 | Version bump + build + deploy | All |

Tasks 1, 2, 3 can be done in parallel. Tasks 5 and 7 can partially overlap. Task 8 depends on everything else.
