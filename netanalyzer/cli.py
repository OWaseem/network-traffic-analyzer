import argparse
import sys
from pathlib import Path

from .detections import run_all
from .loader import read_pcap
from .report import to_json, to_markdown


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="netanalyzer", description="Summarize a pcap and flag suspicious network behavior.")
    p.add_argument("pcap", type=Path)
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--top", type=int, default=5, help="rows in the top-talker and top-port tables")
    p.add_argument("--out", type=Path)
    a = p.parse_args(argv)
    records = list(read_pcap(a.pcap))
    findings = run_all(records)
    text = to_json(findings) if a.format == "json" else to_markdown(records, findings, a.top)
    a.out.write_text(text) if a.out else sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
