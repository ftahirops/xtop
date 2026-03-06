// SPDX-License-Identifier: GPL-2.0
// tlsfinger.c — TLS ClientHello simplified JA3 fingerprinting (watchdog)
//
// TC ingress classifier that identifies TLS ClientHello messages on port 443,
// extracts the TLS version and initial cipher suites, and computes a
// simplified FNV-1a hash as a JA3-like fingerprint.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define ETH_P_IP     0x0800
#define IPPROTO_TCP  6
#define TLS_PORT     443
#define TC_ACT_OK    0

// TLS constants
#define TLS_CONTENT_HANDSHAKE  22
#define TLS_HANDSHAKE_CLIENT_HELLO 1

// FNV-1a constants
#define FNV_OFFSET_BASIS 0x811c9dc5U
#define FNV_PRIME        0x01000193U

struct ja3_val {
    __u64 count;
    __u32 sample_saddr;
    __u32 sample_daddr;
    __u16 tls_version;
    __u16 cipher_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 512);
    __type(key, __u32);
    __type(value, struct ja3_val);
} ja3_accum SEC(".maps");

static __always_inline __u32 fnv1a(__u32 hash, __u8 byte)
{
    hash ^= (__u32)byte;
    hash *= FNV_PRIME;
    return hash;
}

SEC("tc")
int handle_tlsfinger(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u8 ihl = ip->ihl * 4;
    if (ihl < 20)
        return TC_ACT_OK;
    if (ihl > 60)
        return TC_ACT_OK;

    // Parse TCP header — validate bounds before forming pointer
    if ((void *)ip + ihl + sizeof(struct tcphdr) > data_end)
        return TC_ACT_OK;
    struct tcphdr *tcp = (void *)ip + ihl;

    // Filter: destination port 443
    if (tcp->dest != __builtin_bswap16(TLS_PORT))
        return TC_ACT_OK;

    // Compute TCP header length (doff is data offset in 4-byte units)
    __u8 tcp_hlen = tcp->doff * 4;
    if (tcp_hlen < 20)
        return TC_ACT_OK;

    // TLS record starts after TCP header
    __u8 *tls = (__u8 *)tcp + tcp_hlen;

    // TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
    if ((void *)(tls + 5) > data_end)
        return TC_ACT_OK;

    // Check content type: must be Handshake (22)
    if (tls[0] != TLS_CONTENT_HANDSHAKE)
        return TC_ACT_OK;

    // Handshake header starts at tls+5: type(1) + length(3) = 4 bytes
    __u8 *hs = tls + 5;
    if ((void *)(hs + 4) > data_end)
        return TC_ACT_OK;

    // Check handshake type: must be ClientHello (1)
    if (hs[0] != TLS_HANDSHAKE_CLIENT_HELLO)
        return TC_ACT_OK;

    // ClientHello body starts at hs+4
    // ClientHello layout:
    //   client_version(2) + random(32) + session_id_length(1) ...
    __u8 *ch = hs + 4;

    // Need at least version(2) + random(32) + session_id_len(1) = 35 bytes
    if ((void *)(ch + 35) > data_end)
        return TC_ACT_OK;

    // TLS version from ClientHello (bytes 0-1)
    __u16 tls_version = ((__u16)ch[0] << 8) | (__u16)ch[1];

    // Session ID length at offset 34
    __u8 sess_id_len = ch[34];
    if (sess_id_len > 32) // session ID max 32 bytes
        return TC_ACT_OK;

    // Cipher suites list starts after session ID
    // Bounds check BEFORE forming pointer: need ch + 35 + sess_id_len + 2 (for cipher_list_len)
    if ((void *)(ch + 35 + sess_id_len + 2) > data_end)
        return TC_ACT_OK;
    __u8 *cipher_start = ch + 35 + sess_id_len;

    __u16 cipher_list_len = ((__u16)cipher_start[0] << 8) | (__u16)cipher_start[1];

    // Clamp cipher_list_len to remaining data to prevent out-of-bounds reads
    __u32 remaining = (unsigned long)data_end - (unsigned long)(cipher_start + 2);
    if (cipher_list_len > remaining)
        cipher_list_len = (__u16)remaining;
    __u16 cipher_count = cipher_list_len / 2; // each cipher suite is 2 bytes

    // Read up to first 8 bytes (4 cipher suites) for fingerprinting
    __u8 *ciphers = cipher_start + 2;

    // Compute FNV-1a hash over TLS version + first 8 cipher bytes
    __u32 hash = FNV_OFFSET_BASIS;
    hash = fnv1a(hash, (__u8)(tls_version >> 8));
    hash = fnv1a(hash, (__u8)(tls_version & 0xFF));

    // Hash up to 8 bytes of cipher data
    __u8 max_cipher_bytes = 8;
    if (cipher_list_len < max_cipher_bytes)
        max_cipher_bytes = (__u8)cipher_list_len;

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i >= max_cipher_bytes)
            break;
        __u8 *b = ciphers + i;
        if ((void *)(b + 1) > data_end)
            break;
        hash = fnv1a(hash, *b);
    }

    // Store/update fingerprint
    struct ja3_val *val = bpf_map_lookup_elem(&ja3_accum, &hash);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
        val->sample_saddr = ip->saddr;
        val->sample_daddr = ip->daddr;
        val->tls_version = tls_version;
        val->cipher_count = cipher_count;
    } else {
        struct ja3_val new_val = {
            .count = 1,
            .sample_saddr = ip->saddr,
            .sample_daddr = ip->daddr,
            .tls_version = tls_version,
            .cipher_count = cipher_count,
        };
        bpf_map_update_elem(&ja3_accum, &hash, &new_val, BPF_ANY);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
