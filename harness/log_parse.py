#!/usr/bin/env python3
"""log_parse.py - parse a DanderSpritz LP XML log into structured records."""
import argparse, json, sys
import xml.etree.ElementTree as ET

WANTED = {"PayloadInfo", "RunLibrary", "LibraryInfo", "FileInfo",
          "Payload", "Command", "File", "Executable"}

# Ground-truth fields extracted from PayloadInfo records
GROUND_TRUTH_FIELDS = {"sendsize", "checksum", "flags", "runType", "export",
                       "origSize", "libraryType"}


def walk(node, out, path=""):
    tag = node.tag.split("}")[-1]
    here = f"{path}/{tag}"
    if tag in WANTED:
        rec = {"element": tag, "path": here, "attrs": dict(node.attrib)}
        txt = (node.text or "").strip()
        if txt:
            rec["text"] = txt
        out.append(rec)
    for ch in node:
        walk(ch, out, here)


def ground_truth(recs):
    """Extract ground-truth values from PayloadInfo records for verify.py."""
    vals = {}
    for r in recs:
        if r["element"] != "PayloadInfo":
            continue
        attrs = r["attrs"]
        for k in GROUND_TRUTH_FIELDS:
            if k in attrs:
                vals[k] = attrs[k]
    return vals


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ground-truth", action="store_true",
                    help="print ground-truth values as key=value lines")
    a = ap.parse_args()
    recs = []
    walk(ET.parse(a.log).getroot(), recs)
    if a.json:
        print(json.dumps(recs, indent=2))
        return 0
    print(f"{len(recs)} records from {a.log}\n")
    vals = set()
    for r in recs:
        print(f"{r['element']:<12} " + " ".join(f"{k}={v}" for k, v in sorted(r["attrs"].items())))
        for k, v in r["attrs"].items():
            if k.lower() in ("checksum", "origsize", "sendsize", "flags", "export"):
                vals.add(f"{k}={v}")
    if vals:
        print("\nground-truth values for verify.py:")
        for v in sorted(vals):
            print("  " + v)
    if a.ground_truth:
        gt = ground_truth(recs)
        print("\n-- ground-truth --")
        for k in sorted(gt):
            print(f"{k}={gt[k]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
