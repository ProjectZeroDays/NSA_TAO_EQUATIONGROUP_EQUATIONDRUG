#!/usr/bin/env python3
"""flags.py - find the PCHEAP flag name/value table in PCConfig.exe.

The nine names form one contiguous UTF-16 blob and are table-referenced, so no
VA appears as an immediate in .text. This hunts the pointer table and dumps the
dwords on either side of it.
"""
import re, struct, subprocess, sys


def wide(b, pat):
    return [(m.start(), m.group().decode("utf-16le", "replace"))
            for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", b)
            if pat.search(m.group().decode("utf-16le", "replace"))]


def pe_ctx(b):
    e = struct.unpack_from("<I", b, 0x3c)[0]
    nsec = struct.unpack_from("<H", b, e + 6)[0]
    optsz = struct.unpack_from("<H", b, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", b, opt)[0]
    base = struct.unpack_from("<Q" if magic == 0x20b else "<I", b, opt + (24 if magic == 0x20b else 28))[0]
    secs = []
    for i in range(nsec):
        s = opt + optsz + i * 40
        vs, va, raw, praw = struct.unpack_from("<IIII", b, s + 8)
        secs.append((praw, raw, va))
    return base, secs


def main(path):
    b = open(path, "rb").read()
    base, secs = pe_ctx(b)

    def off2va(off):
        for praw, raw, va in secs:
            if praw <= off < praw + raw:
                return base + va + (off - praw)
        return -1

    hits = wide(b, re.compile(r"PCHEAP_CONFIG_"))
    if not hits:
        print("no PCHEAP_CONFIG_* strings")
        return 1
    print(f"{len(hits)} flag names")
    vas = []
    for off, s in hits:
        v = off2va(off)
        vas.append(v)
        print(f"  {v:#010x}  {s}")

    r = subprocess.run(["objdump", "-d", "--no-show-raw-insn", path],
                       capture_output=True, text=True)
    print(f"objdump lines: {len(r.stdout.splitlines())}  stderr={r.stderr.strip()[:100]!r}")

    needle = struct.pack("<I", vas[0])
    start, found = 0, []
    while True:
        i = b.find(needle, start)
        if i < 0:
            break
        n = 0
        for k, v in enumerate(vas):
            p = i + k * 4
            if p + 4 <= len(b) and struct.unpack_from("<I", b, p)[0] == v:
                n += 1
            else:
                break
        if n >= 3:
            found.append((i, n))
        start = i + 1

    if not found:
        print("\nno contiguous pointer table found - dumping the region around the names")
        lo = max(0, hits[0][0] - 0x40)
        hi = min(len(b), hits[-1][0] + 0x140)
        for p in range(lo, hi, 16):
            row = b[p:p + 16]
            print(f"  {p:#08x}  " + " ".join(f"{x:02x}" for x in row))
        return 0

    for off, n in found:
        print(f"\npointer table @ file {off:#x} (va {off2va(off):#x}), {n} entries")
        print("  -- before --")
        for p in range(max(0, off - 0x60), off, 4):
            v = struct.unpack_from("<I", b, p)[0]
            print(f"   {p:#08x}  {v:#010x}")
        print("  -- table --")
        for k in range(n):
            p = off + k * 4
            v = struct.unpack_from("<I", b, p)[0]
            tag = " <- " + hits[vas.index(v)][1] if v in vas else ""
            print(f"   {p:#08x}  {v:#010x}{tag}")
        print("  -- after --")
        for p in range(off + n * 4, min(len(b), off + n * 4 + 0x60), 4):
            print(f"   {p:#08x}  {struct.unpack_from('<I', b, p)[0]:#010x}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
