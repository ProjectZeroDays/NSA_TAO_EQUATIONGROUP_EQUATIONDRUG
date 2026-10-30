#!/usr/bin/env python3
"""run_all.py - run extract.py over every capture and assert none are empty."""
import argparse, json, os, subprocess, sys

REPO = "https://github.com/johnbergbom/PeddleCheap.git"
CAPTURES = [
    ("forward_level3_tcp_port_1163.pcap", "tcp", 1163),
    ("forward_level4_tcp_port_1167.pcap", "tcp", 1167),
    ("reverse_level3_http_port_80.pcap", "http", 80),
    ("reverse_level3_http_port_443.pcap", "http", 443),
    ("reverse_level3_tcp_port_53.pcap", "tcp", 53),
]

HERE = os.path.dirname(os.path.abspath(__file__))
EXTRACT = os.path.join(HERE, "extract.py")


def selftest():
    r = subprocess.run([sys.executable, EXTRACT, "--selftest"], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def run_one(path, port=None):
    cmd = [sys.executable, EXTRACT, path, "--json"]
    if port is not None:
        cmd.extend(["--port", str(port)])
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, (r.stderr.strip() or f"exit {r.returncode}")
    try:
        return json.loads(r.stdout), ""
    except Exception as e:
        return None, f"bad json: {e}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", nargs="?", default=".")
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--port-only", action="store_true",
                    help="require at least one frame on the capture's own port")
    a = ap.parse_args()

    ok, msg = selftest()
    if not ok:
        print(f"extract.py selftest FAILED: {msg}")
        return 2

    if a.fetch:
        dest = os.path.join(a.dir, "caps")
        if not os.path.isdir(dest):
            subprocess.run(["git", "clone", "--depth", "1", REPO, dest], check=True)
        a.dir = dest

    summary, dead = [], []
    for name, transport, port in CAPTURES:
        path = os.path.join(a.dir, name)
        if not os.path.exists(path):
            summary.append({"capture": name, "transport": transport, "port": port,
                            "frames": None, "status": "MISSING"})
            dead.append(name)
            continue
        recs, err = run_one(path, port if a.port_only else None)
        if recs is None:
            summary.append({"capture": name, "transport": transport, "port": port,
                            "frames": None, "status": "PARSE-FAIL", "error": err})
            dead.append(name)
            continue
        dirs = sorted({r["direction"] for r in recs})
        if not recs:
            dead.append(name)
        summary.append({"capture": name, "transport": transport, "port": port,
                        "frames": len(recs), "directions": dirs,
                        "status": "OK" if recs else "EMPTY"})

    if a.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"{'capture':<38}{'transport':<11}{'port':>6}{'frames':>8}  {'directions':<22}status")
        print("-" * 96)
        for s in summary:
            fr = "-" if s["frames"] is None else str(s["frames"])
            print(f"{s['capture']:<38}{s['transport']:<11}{s['port']:>6}{fr:>8}  "
                  f"{','.join(s.get('directions', [])) or '-':<22}{s['status']}")
        print()
        print(f"FAIL: {len(dead)}/{len(CAPTURES)} unusable: {dead}" if dead
              else f"PASS: all {len(CAPTURES)} captures yielded frames "
             f"({sum(s['frames'] for s in summary)} total)")

    return 1 if dead else 0


if __name__ == "__main__":
    sys.exit(main())