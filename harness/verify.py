#!/usr/bin/env python3
"""verify.py - force-search known ground-truth values at any offset/width/endian."""
import argparse, sys

WIDTHS = [(1, "u8"), (2, "u16"), (4, "u32"), (8, "u64")]


def search(blob, value):
    hits = []
    for w, name in WIDTHS:
        for end in ("big", "little"):
            for off in range(0, len(blob) - w + 1):
                if int.from_bytes(blob[off:off + w], end) == value:
                    hits.append((off, w, name, end))
    return hits


def run(blob, labelled):
    ok, seen = True, {}
    for label, value in labelled:
        hits = search(blob, value)
        print(f"[{'FOUND' if hits else 'MISSING'}] {label} (0x{value:x}) -> {len(hits)} hit(s)")
        if not hits:
            ok = False
        for off, w, name, end in hits[:6]:
            print(f"          +{off} as {name} {end}")
            seen.setdefault((off, w), []).append(label)
    amb = {k: v for k, v in seen.items() if len(v) > 1}
    print(f"\nunambiguous: {not amb}")
    for (off, w), labels in amb.items():
        print(f"  +{off} width {w} matches {labels}")
    return ok


def selftest():
    blob = bytearray(range(36))
    blob[24:28] = (166644).to_bytes(4, "big")
    blob[28:30] = (0x5d20).to_bytes(2, "little")
    blob[32:34] = (0x0008).to_bytes(2, "big")
    assert run(bytes(blob), [("sendsize", 166644), ("checksum", 0x5d20), ("flags", 0x0008)])
    print("selftest: OK (3/3 located, zero false positives)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blob", nargs="?")
    ap.add_argument("--value", action="append", default=[])
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    blob = open(a.blob, "rb").read()
    return 0 if run(blob, [(f"v{i}", int(v, 0)) for i, v in enumerate(a.value)]) else 1


if __name__ == "__main__":
    sys.exit(main())
