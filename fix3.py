#!/usr/bin/env python3
"""fix3.py - rewrite extract.py correctly, add flags.py + dump.py, extend run.sh."""
import os, re

os.makedirs("harness", exist_ok=True)

open("harness/extract.py", "w", encoding="utf-8", newline="\n").write(r'''#!/usr/bin/env python3
"""extract.py - PeddleCheap frame extractor (HTTP + raw TCP), dependency-free."""
import argparse, json, re, struct, sys
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, TCP
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

HDR_IMPLANT, HDR_LP, BLOCK = 8, 16, 16
MAX_CLEAR = 0x100000


class Frame:
    __slots__ = ("transport", "direction", "seq", "clear_len", "length2", "encr", "ciphertext")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    def as_dict(self):
        d = {k: getattr(self, k) for k in self.__slots__}
        d["ciphertext"] = self.ciphertext.hex()
        return d


def _read_pcap_pure(path):
    data = open(path, "rb").read()
    m = data[:4]
    if m == b"\xd4\xc3\xb2\xa1":
        e = "<"
    elif m == b"\xa1\xb2\xc3\xd4":
        e = ">"
    else:
        raise ValueError("not a pcap")
    link = struct.unpack_from(e + "I", data, 20)[0]
    off, out = 24, []
    while off + 16 <= len(data):
        incl = struct.unpack_from(e + "I", data, off + 8)[0]
        if off + 16 + incl > len(data):
            break
        p = data[off + 16:off + 16 + incl]
        off += 16 + incl
        if link != 1 or len(p) < 34:
            continue
        o = 14
        if p[12:14] == b"\x81\x00":
            o += 4
        if p[o + 9] != 6:
            continue
        t = o + (p[o] & 0x0F) * 4
        src = ".".join(str(x) for x in p[o + 12:o + 16])
        dst = ".".join(str(x) for x in p[o + 16:o + 20])
        sp = (p[t] << 8) | p[t + 1]
        dp = (p[t + 2] << 8) | p[t + 3]
        dof = ((p[t + 12] >> 4) & 0x0F) * 4
        seq = struct.unpack(">I", p[t + 4:t + 8])[0]
        payload = p[t + dof:]
        if payload:
            out.append((src, sp, dst, dp, seq, payload))
    return out


def _concat(chunks):
    chunks.sort(key=lambda c: c[0])
    out, expect = b"", chunks[0][0] if chunks else 0
    for seq, payload in chunks:
        if seq + len(payload) <= expect:
            continue
        start = expect - seq if seq < expect else 0
        out += payload[start:]
        expect = max(expect, seq + len(payload))
    return out


def tcp_streams(pcap):
    if HAVE_SCAPY:
        g = defaultdict(list)
        for pkt in rdpcap(pcap):
            if IP in pkt and TCP in pkt and bytes(pkt[TCP].payload):
                k = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                g[k].append((pkt[TCP].seq, bytes(pkt[TCP].payload)))
        return {k: _concat(v) for k, v in g.items()}
    g = defaultdict(list)
    for src, sp, dst, dp, seq, payload in _read_pcap_pure(pcap):
        g[(src, sp, dst, dp)].append((seq, payload))
    return {k: _concat(v) for k, v in g.items()}


def http_body(buf):
    i = buf.find(b"\r\n\r\n")
    if i < 0:
        return b""
    hdr = buf[:i].decode("latin-1", "replace")
    m = re.search(r"Content-Length:\s*(\d+)", hdr, re.I)
    n = int(m.group(1)) if m else len(buf) - i - 4
    return buf[i + 4:i + 4 + n]


def classify(buf):
    head = buf[:64]
    if head.startswith(b"POST /") or b"POST / HTTP/1." in head:
        return "implant->lp", "http"
    if b"HTTP/1.0 200 OK" in head or b"HTTP/1.1 200 OK" in head:
        return "lp->implant", "http"
    return None, "tcp"


def parse_frames(buf, direction, transport, first16=True):
    """Field offsets follow the header actually in use: 16-byte LP header has
    seq@+4 clear@+8 len2@+12 encr@+13; 8-byte header has clear@+0 len2@+4 encr@+5.
    Only the first frame of an LP->implant body carries the 16-byte header."""
    frames, off, resync, first = [], 0, 0, True
    while True:
        if direction == "implant->lp":
            hlen = HDR_IMPLANT
        else:
            hlen = HDR_LP if (first16 and first) else HDR_IMPLANT
        if off + hlen > len(buf):
            break
        if hlen == HDR_LP:
            seq = struct.unpack_from("<I", buf, off + 4)[0]
            clear = struct.unpack_from(">I", buf, off + 8)[0]
            length2, encr = buf[off + 12], buf[off + 13]
        else:
            clear = struct.unpack_from(">I", buf, off)[0]
            length2, encr, seq = buf[off + 4], buf[off + 5], None
        plen = clear + length2
        if clear > MAX_CLEAR or plen == 0:
            off += 1
            resync += 1
            continue
        end = off + hlen + plen
        if end > len(buf):
            break
        frames.append(Frame(transport=transport, direction=direction, seq=seq,
                            clear_len=clear, length2=length2, encr=encr,
                            ciphertext=buf[off + hlen:end]))
        off = end
        first = False
    return frames, resync


def pick_direction(buf, transport):
    best, best_frames, best_score = None, [], -1
    for d in ("implant->lp", "lp->implant"):
        for f16 in (True, False):
            fr, rs = parse_frames(buf, d, transport, f16)
            if len(fr) - rs > best_score:
                best, best_frames, best_score = d, fr, len(fr) - rs
    return best, best_frames


def extract(pcap):
    records = []
    for buf in tcp_streams(pcap).values():
        direction, transport = classify(buf)
        if transport == "http":
            body = http_body(buf)
            if not body:
                continue
            frames, _ = parse_frames(body, direction, "http")
        else:
            _, frames = pick_direction(buf, "tcp")
        records.extend(frames)
    return records


def selftest():
    hdr = struct.pack(">I", 4) + bytes([12, 1, 0, 0])
    fr, rs = parse_frames(hdr + b"\xAA" * 16, "implant->lp", "tcp")
    assert len(fr) == 1 and rs == 0 and fr[0].clear_len == 4 and fr[0].length2 == 12
    hdr2 = b"\x00" * 4 + struct.pack("<I", 0x2A) + struct.pack(">I", 8) + bytes([8, 1, 0, 0])
    fr2, _ = parse_frames(hdr2 + b"\xBB" * 16, "lp->implant", "tcp")
    assert len(fr2) == 1 and fr2[0].seq == 0x2A
    two = hdr2 + b"\xBB" * 16 + struct.pack(">I", 8) + bytes([8, 0, 0, 0]) + b"\xCC" * 16
    fr3, _ = parse_frames(two, "lp->implant", "tcp")
    assert len(fr3) == 2 and fr3[1].encr == 0 and fr3[1].clear_len == 8
    print("selftest: OK (3 frame shapes, mixed headers, 24-byte invariant held)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    recs = extract(a.pcap)
    if a.json:
        print(json.dumps([r.as_dict() for r in recs], indent=2))
    else:
        for r in recs:
            print(f"{r.transport:5} {r.direction:11} seq={r.seq} clear={r.clear_len} "
                  f"len2={r.length2} encr={r.encr} ct={len(r.ciphertext)}B")
    print(f"-- {len(recs)} frames", file=sys.stderr)


if __name__ == "__main__":
    main()
''')

open("harness/dump.py", "w", encoding="utf-8", newline="\n").write(r'''#!/usr/bin/env python3
"""dump.py - print a disassembly window around a VA, plus objdump diagnostics."""
import re, subprocess, sys


def main():
    if len(sys.argv) < 3:
        print("usage: dump.py <pe> <va-hex> [span-hex]")
        return 2
    path, va = sys.argv[1], int(sys.argv[2], 16)
    span = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x300
    r = subprocess.run(["objdump", "-d", "--no-show-raw-insn", path],
                       capture_output=True, text=True)
    lines = r.stdout.splitlines()
    print(f"# objdump: {len(lines)} lines, stderr={r.stderr.strip()[:120]!r}")
    lo, hi = va - span, va + span
    n = 0
    for l in lines:
        m = re.match(r"\s*([0-9a-f]+):", l)
        if not m:
            continue
        a = int(m.group(1), 16)
        if lo <= a <= hi:
            print(l.rstrip())
            n += 1
    print(f"# {n} lines in 0x{lo:x}..0x{hi:x}")


if __name__ == "__main__":
    sys.exit(main())
''')

open("harness/flags.py", "w", encoding="utf-8", newline="\n").write(r'''#!/usr/bin/env python3
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
''')

sh = open("run.sh", encoding="utf-8").read()
if "harness/flags.py" not in sh:
    sh = sh.replace('hdr "log parser"', '''hdr "flag value table and disassembly"
python3 harness/flags.py bins/PCConfig.exe 2>&1 | tee results/flags.txt || true
{
  python3 harness/dump.py caps/PeddleCheap_Lp.dll 0x1000df00
  python3 harness/dump.py caps/PeddleCheap_Lp.dll 0x1000c7e0
  python3 harness/dump.py caps/PeddleCheap_Lp.dll 0x1000c000
} > results/lp_dump.txt 2>&1 || true

hdr "log parser"''')
    open("run.sh", "w", encoding="utf-8", newline="\n").write(sh)
    print("  extended run.sh")

print("\ndone.  run:")
print("  python3 harness/extract.py --selftest")
print("  python3 harness/run_all.py caps")
print("  python3 harness/flags.py bins/PCConfig.exe")
print("  export GH_PAT=<token> && ./run.sh")