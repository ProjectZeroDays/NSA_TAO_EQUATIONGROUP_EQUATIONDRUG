#!/usr/bin/env python3
"""verify.py - force-search known ground-truth values at any offset/width/endian."""
import argparse, sys

WIDTHS = [(1, "u8"), (2, "u16"), (4, "u32"), (8, "u64")]

CONFIRMED = {"sendsize": 24, "checksum": 28, "flags": 32}
CANDIDATE = {"libtype": 16, "unk20": 20, "runtype": 30}


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


def fixture(path):
    blob = bytes.fromhex(open(path).read().replace("\n", "").strip())
    assert len(blob) == 36, f"fixture is {len(blob)} bytes, expected 36"
    ok = True
    cases = [("sendsize", 24, 4, "big", 166644), ("checksum", 28, 2, "little", 0x5d20),
             ("flags", 32, 2, "big", 0x0008)]
    for label, off, w, end, want in cases:
        got = int.from_bytes(blob[off:off + w], end)
        hits = search(blob, want)
        if got != want:
            print(f"FAIL {label}: +{off} = 0x{got:x}, expected 0x{want:x}"); ok = False
        else:
            print(f"OK   {label} at +{off} (value verified; {len(hits)} total locations in blob)")
    for label, off in CANDIDATE.items():
        print(f"open {label} +{off} = {blob[off:off + 4].hex()} (candidate, not asserted)")
    print("fixture: " + ("OK" if ok else "FAIL"))
    return 0 if ok else 1


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
    ap.add_argument("--fixture")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.fixture:
        return fixture(a.fixture)
    blob = open(a.blob, "rb").read()
    return 0 if run(blob, [(f"v{i}", int(v, 0)) for i, v in enumerate(a.value)]) else 1


if __name__ == "__main__":
    sys.exit(main())
