from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PacketRecord:
    ts: float
    src: str
    dst: str
    proto: str            # TCP, UDP, ICMP, or OTHER
    length: int
    sport: Optional[int] = None
    dport: Optional[int] = None
    tcp_flags: str = ""   # e.g. "S", "SA", "PA"
    icmp_type: Optional[int] = None
    dns_qname: Optional[str] = None


@dataclass
class Finding:
    rule: str
    severity: str  # info | medium | high
    src: str
    detail: str
    mitre: str = ""
    count: int = 0

    def to_dict(self):
        return self.__dict__.copy()
