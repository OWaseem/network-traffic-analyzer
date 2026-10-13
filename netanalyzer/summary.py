"""Traffic statistics: protocol mix, top talkers, top ports, and a flow table."""
from collections import Counter, defaultdict
from typing import Dict, List, Sequence, Tuple

from .models import PacketRecord


def protocol_mix(records: Sequence[PacketRecord]) -> Dict[str, int]:
    return dict(Counter(r.proto for r in records).most_common())


def top_talkers(records: Sequence[PacketRecord], n=5) -> List[Tuple[str, int, int]]:
    """(source IP, packets, bytes) sorted by bytes sent."""
    pk, by = Counter(), Counter()
    for r in records:
        pk[r.src] += 1
        by[r.src] += r.length
    return [(ip, pk[ip], b) for ip, b in by.most_common(n)]


def top_dest_ports(records: Sequence[PacketRecord], n=5) -> List[Tuple[int, int]]:
    c = Counter(r.dport for r in records if r.dport is not None and r.proto in ("TCP", "UDP"))
    return c.most_common(n)


def flows(records: Sequence[PacketRecord]):
    """Unidirectional 5-tuple flows with packet/byte counts and duration."""
    table = defaultdict(lambda: {"packets": 0, "bytes": 0, "first": None, "last": None})
    for r in records:
        key = (r.src, r.sport, r.dst, r.dport, r.proto)
        f = table[key]
        f["packets"] += 1
        f["bytes"] += r.length
        f["first"] = r.ts if f["first"] is None else min(f["first"], r.ts)
        f["last"] = r.ts if f["last"] is None else max(f["last"], r.ts)
    return [{"src": k[0], "sport": k[1], "dst": k[2], "dport": k[3], "proto": k[4], **v,
             "duration": round(v["last"] - v["first"], 3)} for k, v in table.items()]
