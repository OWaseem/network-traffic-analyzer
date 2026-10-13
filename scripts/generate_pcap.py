"""Generate a SYNTHETIC capture with embedded scenarios (no real traffic is used).

Internal hosts are 10.0.0.0/24; external hosts use RFC 5737 documentation ranges.
"""
import random
import string
from pathlib import Path

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

random.seed(11)
OUT = Path(__file__).resolve().parent.parent / "data"
pkts = []
T = 1_760_000_000.0


def add(pkt, t):
    pkt.time = t
    pkts.append(pkt)


def mk(ip, l4):
    return Ether() / ip / l4


def normal_traffic():
    web = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
    for _ in range(600):
        src = f"10.0.0.{random.randint(10, 20)}"
        t = T + random.uniform(0, 600)
        add(mk(IP(src=src, dst=random.choice(web)), TCP(sport=random.randint(40000, 60000), dport=443, flags="PA") / Raw(b"x" * random.randint(40, 500))), t)
        if random.random() < 0.3:
            name = random.choice(["example.com", "news.example.org", "mail.example.net", "cdn.example.com"])
            add(mk(IP(src=src, dst="10.0.0.2"), UDP(sport=random.randint(40000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=name))), t + 0.01)


def port_scan():  # one external host SYN-scans one internal server
    for i, port in enumerate(range(1, 201)):
        add(mk(IP(src="203.0.113.66", dst="10.0.0.5"), TCP(sport=44444, dport=port, flags="S")), T + 100 + i * 0.05)


def ping_sweep():  # one external host pings the whole subnet
    for i in range(1, 61):
        add(mk(IP(src="203.0.113.67", dst=f"10.0.0.{i}"), ICMP(type=8)), T + 200 + i * 0.1)


def dns_tunnel():  # one internal host encodes data into long random subdomains
    for i in range(40):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=36))
        add(mk(IP(src="10.0.0.25", dst="10.0.0.2"), UDP(sport=51000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=f"{label}.tunnel.example-bad.test"))), T + 300 + i * 2)


def big_upload():  # one internal host sends about 0.9 MB to a single external host
    for i in range(650):
        add(mk(IP(src="10.0.0.31", dst="198.51.100.200"), TCP(sport=52000, dport=443, flags="PA") / Raw(b"d" * 1380)), T + 400 + i * 0.05)


def cleartext():  # a legacy telnet login attempt
    add(mk(IP(src="10.0.0.40", dst="10.0.0.9"), TCP(sport=53000, dport=23, flags="S")), T + 500)


if __name__ == "__main__":
    for fn in (normal_traffic, port_scan, ping_sweep, dns_tunnel, big_upload, cleartext):
        fn()
    pkts.sort(key=lambda p: p.time)
    OUT.mkdir(exist_ok=True)
    wrpcap(str(OUT / "sample.pcap"), pkts)
    print(f"wrote {len(pkts)} packets to {OUT / 'sample.pcap'}")
