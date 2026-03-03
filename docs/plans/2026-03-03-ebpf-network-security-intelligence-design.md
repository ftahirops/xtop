# eBPF Network Security Intelligence — Design Document

**Date:** 2026-03-03
**Version target:** 0.21.0

## Goal

Add deep network security analysis to xtop using eBPF probes spanning L1 (metadata/rates), L2 (flow analysis), and L3 (header inspection). Detect DDoS, port scans, C2 beacons, DNS tunneling, data exfiltration, and lateral movement in real time with < 1% CPU overhead for always-on probes.

## Architecture

**Approach: Sentinel-Heavy with Watchdog Escalation**

5 new always-on Sentinel BPF probes handle L1 counting in kernel space (near-zero CPU). When anomaly thresholds fire, 4 Watchdog probes auto-attach for L2/L3 deep inspection (TC ingress hooks for packet header analysis). All results feed into the existing RCA engine with new security-specific evidence, patterns, and causal rules. UI enhancement on the Security page (L) with 5 new collapsible sections.

## New BPF Probes

### Sentinel Probes (Always-On, 5 new)

| Probe | Hook | Map Type | Key | Detection |
|-------|------|----------|-----|-----------|
| synflood | tracepoint tcp_retransmit_synack + kprobe tcp_conn_request | LRU hash (4096) | src IP | SYN rate >1000/s, half-open ratio >50% |
| portscan | kprobe tcp_v4_send_reset | LRU hash (2048) | src IP | >20 RSTs + >10 unique port buckets/30s |
| dnsmon | kprobe udp_sendmsg (port 53 filter) | hash (1024) | PID | >100 queries/s, avg query >60 bytes |
| connrate | tracepoint inet_sock_set_state | LRU hash (8192) | PID+daddr | connect >> close rate, >50 unique dests/min |
| outbound | kprobe tcp_sendmsg | LRU hash (4096) | PID+daddr | >100MB/hr per dest, burst from non-server |

### Watchdog Probes (Auto-Triggered, 4 new)

| Probe | Hook | Trigger | Detection | Duration |
|-------|------|---------|-----------|----------|
| tcpflags | tc_cls_act ingress | sec.portscan fires | XMAS/NULL/FIN/SYN+FIN flag combos | 60s |
| dnsdeep | tc_cls_act ingress+egress | sec.dns.anomaly fires | TXT ratio >50% = tunneling, single domain >90% = C2 | 60s |
| tlsfinger | tc_cls_act ingress (port 443) | sec.beacon or sec.outbound fires | JA3 hash extraction, known-bad fingerprint matching | 60s |
| beacondetect | kprobe tcp_sendmsg (timing) | sec.outbound fires | Inter-packet interval jitter <20% = fixed beacon = C2 | 120s |

## Model Types

### New structs in model/metrics.go

- `SynFloodEntry` — SrcIP, SynCount, SynAckRetrans, HalfOpenRatio
- `PortScanEntry` — SrcIP, RSTCount, UniquePortBuckets, DurationSec
- `DNSAnomalyEntry` — PID, Comm, QueryCount, AvgQueryLen, TotalRespBytes, QueriesPerSec
- `FlowRateEntry` — PID, Comm, DstIP, ConnectCount, CloseCount, UniqueDestCount
- `OutboundEntry` — PID, Comm, DstIP, TotalBytes, PacketCount, BytesPerSec
- `TCPFlagAnomaly` — SrcIP, FlagCombo, Count
- `DNSTunnelIndicator` — PID, Comm, DomainHash, TXTRatio, AvgQueryLen, QueryRate
- `JA3Entry` — Hash, Count, SampleSrc, SampleDst, Known
- `BeaconIndicator` — PID, Comm, DstIP, DstPort, AvgIntervalSec, Jitter, SampleCount

### SentinelData additions

- SynFlood []SynFloodEntry
- PortScans []PortScanEntry
- DNSAnomaly []DNSAnomalyEntry
- FlowRates []FlowRateEntry
- OutboundTop []OutboundEntry

### SecurityMetrics additions (for watchdog results)

- TCPFlagAnomalies []TCPFlagAnomaly
- DNSTunnelIndicators []DNSTunnelIndicator
- JA3Fingerprints []JA3Entry
- BeaconIndicators []BeaconIndicator
- ThreatScore string (CLEAR/ANOMALY/THREAT)
- ActiveWatchdogs []string

## RCA Integration

### 8 New Evidence IDs

| ID | Domain | Threshold (warn,crit) | Measured | Weight Slot |
|----|--------|----------------------|----------|-------------|
| sec.synflood | network | (100, 1000) SYN/s per IP | true | psi |
| sec.portscan | network | (10, 30) unique port buckets | true | latency |
| sec.dns.anomaly | network | (50, 200) queries/s per PID | true | queue |
| sec.dns.tunnel | network | (0.3, 0.7) TXT ratio | true | psi |
| sec.outbound.exfil | network | (50MB, 500MB) /hr per dest | true | latency |
| sec.lateral | network | (20, 50) unique dests per PID | true | queue |
| sec.beacon | network | (0, 0.2) jitter (inverted: lower=worse) | true | psi |
| sec.tcp.flags | network | (1, 10) anomalous flag pkts | true | secondary |

### 6 New Patterns

| Priority | Name | Conditions | MinMatch |
|----------|------|-----------|----------|
| 70 | DDoS SYN Flood | sec.synflood + net.conntrack.growth | 1 |
| 68 | Port Scan Attack | sec.portscan + sec.tcp.flags | 1 |
| 66 | C2 Beacon Active | sec.beacon + sec.outbound.exfil | 1 |
| 64 | DNS Tunneling | sec.dns.tunnel + sec.dns.anomaly | 2 |
| 62 | Data Exfiltration | sec.outbound.exfil + sec.lateral | 1 |
| 58 | Network Reconnaissance | sec.portscan + net.tcp.retrans | 1 |

### 8 New Causal Rules

- sec.synflood → net.conntrack.growth (0.9)
- sec.synflood → net.drops (0.8)
- sec.portscan → net.sentinel.resets (0.85)
- sec.dns.anomaly → sec.dns.tunnel (0.7)
- sec.lateral → sec.outbound.exfil (0.75)
- sec.beacon → sec.outbound.exfil (0.6)
- sec.tcp.flags → sec.portscan (0.8)
- sec.synflood → cpu.busy (0.5)

### Watchdog Auto-Trigger Domain

New domain: "Security Threat"
- sec.portscan fires → attach tcpflags
- sec.dns.anomaly fires → attach dnsdeep
- sec.beacon or sec.outbound.exfil fires → attach tlsfinger + beacondetect

## Security Page UI Enhancement

5 new collapsible sections added to existing Security page (L):

1. **NETWORK THREAT OVERVIEW** (section 9) — always-visible summary with threat status, primary/secondary threats, active watchdog countdown
2. **ATTACK DETECTION (BPF)** (section 10) — SYN flood table, port scan table, TCP flag anomalies. Auto-expands on attack.
3. **DNS INTELLIGENCE (BPF)** (section 11) — per-PID DNS stats, TXT ratio, tunneling verdict. Watchdog: top domains.
4. **FLOW INTELLIGENCE (BPF)** (section 12) — outbound volume ranked, lateral movement PIDs, beacon detection sub-table.
5. **TLS FINGERPRINTS (BPF)** (section 13) — JA3 hashes with known-bad matching. Only when watchdog active.

Navigation: same j/k/Enter/A/C pattern. Auto-expand on threat detection.

## Narrative Templates

8 new templates in engine/narrative.go:
- sec.synflood + net.drops → "DDoS SYN flood — half-open connections exhausting resources"
- sec.portscan → "Port scan detected — reconnaissance activity from {IP}"
- sec.dns.tunnel → "DNS tunneling — data exfiltration through DNS queries"
- sec.beacon → "C2 beacon — periodic callbacks to {IP} every {interval}s"
- sec.outbound.exfil → "Data exfiltration — {MB}/hr outbound from {process} to {IP}"
- sec.lateral → "Lateral movement — {process} connecting to {N} internal hosts"
- sec.tcp.flags → "TCP flag anomalies — evasion scan techniques detected"
- sec.dns.anomaly → "DNS anomaly — {process} generating {N} queries/s"

## Temporal Tracking

New cross-signal pairs:
- sec.synflood → net.conntrack.growth ("SYN flood driving conntrack table growth")
- sec.portscan → net.sentinel.resets ("Port scanning causing TCP RST responses")
- sec.dns.anomaly → sec.dns.tunnel ("Elevated DNS leading to tunneling detection")
- sec.beacon → sec.outbound.exfil ("C2 beacon associated with data exfiltration")

New shortLabel entries for all 8 sec.* evidence IDs.

## Explain Panel Glossary

New entries for Security page glossary:
- SYN Flood, Port Scan, DNS Tunneling, C2 Beacon, JA3 Fingerprint, Data Exfiltration, Lateral Movement, TCP Flag Anomaly, Watchdog Probe, Half-Open Ratio, TXT Ratio, Beacon Jitter

## Performance Budget

- 5 Sentinel probes: < 0.3% CPU (pure hash map counter increments, kernel-side aggregation)
- 4 Watchdog probes: < 2% CPU when active (60-120s bursts, TC hooks on packet path)
- Total always-on: < 0.5% CPU
- Peak during investigation: < 2.5% CPU (Sentinel + all Watchdogs)

## Backward Compatibility

- Existing SecurityMetrics struct extended (new fields are additive)
- Existing SentinelData struct extended (new fields are additive)
- Existing security page sections unchanged (new sections appended)
- No breaking changes to any existing functionality
