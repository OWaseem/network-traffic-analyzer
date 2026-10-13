"""Detections over PacketRecords. Thresholds are parameters so they can be tuned."""
import ipaddress
import math
from collections import Counter, defaultdict
from typing import List, Sequence

from .models import Finding, PacketRecord

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 110: "POP3", 143: "IMAP"}


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_private(ip: str) -> bool:
    """True for RFC 1918 internal addresses only.

    ipaddress.is_private is deliberately not used: it also returns True for documentation, loopback,
    and link-local ranges, which would make test-net hosts look internal.
    """
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in _INTERNAL)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def _max_window_distinct(items, window_s):
    """items: list of (ts, value). Returns the largest number of distinct values inside any window."""
    items = sorted(items)
    best, left = 0, 0
    counts = Counter()
    for right in range(len(items)):
        counts[items[right][1]] += 1
        while items[right][0] - items[left][0] > window_s:
            counts[items[left][1]] -= 1
            if counts[items[left][1]] == 0:
                del counts[items[left][1]]
            left += 1
        best = max(best, len(counts))
    return best


def port_scan(records: Sequence[PacketRecord], min_ports=20, window_s=60) -> List[Finding]:
    """A source sending bare SYNs to many distinct ports on one host (MITRE T1046)."""
    by_pair = defaultdict(list)
    for r in records:
        if r.proto == "TCP" and r.tcp_flags == "S" and r.dport is not None:
            by_pair[(r.src, r.dst)].append((r.ts, r.dport))
    out = []
    for (src, dst), items in by_pair.items():
        n = _max_window_distinct(items, window_s)
        if n >= min_ports:
            out.append(Finding("port_scan", "high", src, f"SYNs to {n} distinct ports on {dst} within {window_s}s",
                               "T1046", n))
    return out


def ping_sweep(records: Sequence[PacketRecord], min_hosts=15, window_s=60) -> List[Finding]:
    """A source sending ICMP echo requests to many distinct hosts (MITRE T1018)."""
    by_src = defaultdict(list)
    for r in records:
        if r.proto == "ICMP" and r.icmp_type == 8:
            by_src[r.src].append((r.ts, r.dst))
    out = []
    for src, items in by_src.items():
        n = _max_window_distinct(items, window_s)
        if n >= min_hosts:
            out.append(Finding("ping_sweep", "medium", src, f"ICMP echo requests to {n} distinct hosts within {window_s}s",
                               "T1018", n))
    return out


def dns_tunneling(records: Sequence[PacketRecord], min_queries=10, min_label_len=20, min_entropy=3.4) -> List[Finding]:
    """Many DNS queries with long, high-entropy subdomains under one parent domain (MITRE T1071.004)."""
    suspicious = defaultdict(list)
    for r in records:
        if not r.dns_qname:
            continue
        parts = r.dns_qname.split(".")
        if len(parts) < 3:
            continue
        label, parent = parts[0], ".".join(parts[-2:])
        if len(label) >= min_label_len and shannon_entropy(label) >= min_entropy:
            suspicious[(r.src, parent)].append(label)
    out = []
    for (src, parent), labels in suspicious.items():
        if len(labels) >= min_queries:
            out.append(Finding("dns_tunneling", "high", src,
                               f"{len(labels)} long, high-entropy queries under {parent} (e.g. {labels[0][:24]}...)",
                               "T1071.004", len(labels)))
    return out


def large_upload(records: Sequence[PacketRecord], min_bytes=500_000) -> List[Finding]:
    """Large volume sent from an internal host to a single external IP (possible exfiltration, MITRE T1041)."""
    totals = Counter()
    for r in records:
        if is_private(r.src) and not is_private(r.dst):
            totals[(r.src, r.dst)] += r.length
    return [Finding("large_upload", "medium", src, f"{b/1e6:.2f} MB sent to external host {dst}", "T1041", b)
            for (src, dst), b in totals.items() if b >= min_bytes]


def cleartext_protocols(records: Sequence[PacketRecord]) -> List[Finding]:
    """Internal hosts opening connections with unencrypted protocols (informational)."""
    seen = Counter()
    for r in records:
        if r.proto == "TCP" and r.dport in CLEARTEXT_PORTS and r.tcp_flags == "S" and is_private(r.src):
            seen[(r.src, CLEARTEXT_PORTS[r.dport])] += 1
    return [Finding("cleartext_protocol", "info", src, f"{n} {name} connection attempt(s); traffic is unencrypted",
                    "T1040", n) for (src, name), n in seen.items()]


def run_all(records: Sequence[PacketRecord]) -> List[Finding]:
    f = port_scan(records) + ping_sweep(records) + dns_tunneling(records) + large_upload(records) + cleartext_protocols(records)
    order = {"high": 0, "medium": 1, "info": 2}
    return sorted(f, key=lambda x: (order[x.severity], -x.count))
