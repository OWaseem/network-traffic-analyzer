"""Read a pcap with scapy and convert packets into lightweight PacketRecord objects."""
from typing import Iterator

from .models import PacketRecord


def read_pcap(path: str) -> Iterator[PacketRecord]:
    from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, PcapReader  # imported lazily so detections need no scapy

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            qname = None
            if pkt.haslayer(DNSQR) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            if TCP in pkt:
                yield PacketRecord(float(pkt.time), ip.src, ip.dst, "TCP", len(pkt), int(pkt[TCP].sport),
                                   int(pkt[TCP].dport), str(pkt[TCP].flags), None, qname)
            elif UDP in pkt:
                yield PacketRecord(float(pkt.time), ip.src, ip.dst, "UDP", len(pkt), int(pkt[UDP].sport),
                                   int(pkt[UDP].dport), "", None, qname)
            elif ICMP in pkt:
                yield PacketRecord(float(pkt.time), ip.src, ip.dst, "ICMP", len(pkt), None, None, "", int(pkt[ICMP].type), None)
            else:
                yield PacketRecord(float(pkt.time), ip.src, ip.dst, "OTHER", len(pkt))
