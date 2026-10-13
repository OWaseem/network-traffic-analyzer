import json
import subprocess
import sys
from pathlib import Path

from netanalyzer import detections as d
from netanalyzer import summary
from netanalyzer.models import PacketRecord

ROOT = Path(__file__).resolve().parent.parent


def syn(src, dst, port, ts):
    return PacketRecord(ts, src, dst, "TCP", 60, 40000, port, "S")


def test_entropy_ordering():
    assert d.shannon_entropy("aaaaaaaa") == 0
    assert d.shannon_entropy("a8f3k2m9q1z7x5b0c4v6") > 3.5
    assert d.shannon_entropy("") == 0


def test_is_private():
    assert d.is_private("10.1.2.3") and d.is_private("192.168.0.9")
    assert not d.is_private("203.0.113.5")


def test_port_scan_detected_within_window():
    recs = [syn("9.9.9.9", "10.0.0.5", p, p * 0.1) for p in range(1, 31)]
    f = d.port_scan(recs, min_ports=20, window_s=60)
    assert len(f) == 1 and f[0].count == 30 and f[0].mitre == "T1046"


def test_port_scan_ignores_slow_scans_and_normal_syns():
    slow = [syn("9.9.9.9", "10.0.0.5", p, p * 100) for p in range(1, 31)]  # one port every 100s
    assert d.port_scan(slow, min_ports=20, window_s=60) == []
    same_port = [syn("10.0.0.2", "10.0.0.5", 443, i) for i in range(50)]
    assert d.port_scan(same_port, min_ports=20) == []


def test_ping_sweep():
    recs = [PacketRecord(i, "9.9.9.9", f"10.0.0.{i}", "ICMP", 84, icmp_type=8) for i in range(1, 21)]
    assert len(d.ping_sweep(recs, min_hosts=15)) == 1
    replies = [PacketRecord(i, "9.9.9.9", f"10.0.0.{i}", "ICMP", 84, icmp_type=0) for i in range(1, 21)]
    assert d.ping_sweep(replies, min_hosts=15) == []


def test_dns_tunneling_flags_random_labels_not_normal_names():
    odd = [PacketRecord(i, "10.0.0.25", "10.0.0.2", "UDP", 90, 5000, 53, dns_qname=f"{'a1b2c3d4e5f6g7h8i9j0k'}{i:02d}xq.tunnel.bad.test") for i in range(12)]
    assert len(d.dns_tunneling(odd, min_queries=10)) == 1
    normal = [PacketRecord(i, "10.0.0.11", "10.0.0.2", "UDP", 70, 5000, 53, dns_qname="www.example.com") for i in range(50)]
    assert d.dns_tunneling(normal) == []


def test_large_upload_only_internal_to_external():
    out = [PacketRecord(i, "10.0.0.31", "198.51.100.200", "TCP", 1400, 1, 443, "PA") for i in range(500)]
    assert len(d.large_upload(out, min_bytes=500_000)) == 1
    inbound = [PacketRecord(i, "198.51.100.200", "10.0.0.31", "TCP", 1400, 443, 1, "PA") for i in range(500)]
    assert d.large_upload(inbound, min_bytes=500_000) == []


def test_cleartext_protocol_info_finding():
    f = d.cleartext_protocols([syn("10.0.0.40", "10.0.0.9", 23, 1)])
    assert f and f[0].severity == "info"


def test_summary_stats():
    recs = [PacketRecord(1, "10.0.0.1", "10.0.0.2", "TCP", 100, 1, 443, "PA"),
            PacketRecord(2, "10.0.0.1", "10.0.0.2", "TCP", 300, 1, 443, "PA"),
            PacketRecord(3, "10.0.0.3", "10.0.0.2", "UDP", 50, 2, 53)]
    assert summary.protocol_mix(recs) == {"TCP": 2, "UDP": 1}
    assert summary.top_talkers(recs, 1) == [("10.0.0.1", 2, 400)]
    flow = [f for f in summary.flows(recs) if f["src"] == "10.0.0.1"][0]
    assert flow["packets"] == 2 and flow["bytes"] == 400 and flow["duration"] == 1


def test_end_to_end_on_generated_pcap(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_pcap.py")], check=True)
    out = tmp_path / "r.json"
    subprocess.run([sys.executable, "-m", "netanalyzer", str(ROOT / "data" / "sample.pcap"), "--format", "json", "--out", str(out)],
                   check=True, cwd=ROOT)
    found = {(f["rule"], f["src"]) for f in json.loads(out.read_text())}
    assert ("port_scan", "203.0.113.66") in found
    assert ("ping_sweep", "203.0.113.67") in found
    assert ("dns_tunneling", "10.0.0.25") in found
    assert ("large_upload", "10.0.0.31") in found
    assert ("cleartext_protocol", "10.0.0.40") in found
    assert not any(src in {f"10.0.0.{i}" for i in range(10, 21)} for _, src in found)  # normal clients stay clean
