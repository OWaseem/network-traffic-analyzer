import json
from typing import List, Sequence

from . import summary
from .models import Finding, PacketRecord


def to_markdown(records: Sequence[PacketRecord], findings: List[Finding], top=5) -> str:
    total_bytes = sum(r.length for r in records)
    duration = (max(r.ts for r in records) - min(r.ts for r in records)) if records else 0
    L = ["# Network Traffic Report", "",
         f"- Packets: **{len(records):,}**  |  Bytes: **{total_bytes:,}**  |  Capture length: **{duration:.0f}s**", "",
         "## Protocol mix", ""]
    L += [f"- {p}: {n:,}" for p, n in summary.protocol_mix(records).items()]
    L += ["", "## Top talkers (by bytes sent)", "", "| Source | Packets | Bytes |", "|---|---|---|"]
    L += [f"| {ip} | {p:,} | {b:,} |" for ip, p, b in summary.top_talkers(records, top)]
    L += ["", "## Top destination ports", ""] + [f"- {port}: {n:,} packets" for port, n in summary.top_dest_ports(records, top)]
    L += ["", f"## Findings ({len(findings)})", ""]
    if findings:
        L += ["| Severity | Rule | Source | MITRE | Detail |", "|---|---|---|---|---|"]
        L += [f"| {f.severity} | {f.rule} | {f.src} | {f.mitre} | {f.detail} |" for f in findings]
    else:
        L.append("No findings.")
    return "\n".join(L) + "\n"


def to_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)
