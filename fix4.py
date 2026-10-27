#!/usr/bin/env python3
"""fix4.py - robust pcap reader (pcap+pcapng, multiple link types) + --probe."""
import os, re

os.makedirs("harness", exist_ok=True)

open("harness/pcapread.py", "w", encoding="utf-8", newline="\n").write(r'''#!/usr/bin/env python3
"""pcapread.py - dependency-free pcap/pcapng reader. Returns TCP tuples."""
import struct, sys


def _extract_tcp(p, link):
    if link == 1:                      # Ethernet
        if len(p) < 14:
            return None
        et = (p[12] << 8) | p[13]
        o = 14
        if et == 0x8100:
            o += 4
            et = (p[o - 2] << 8) | p[o - 1]
        if et != 0x0800:
            return None
    elif link in (101, 12, 14, 228):   # raw IP variants
        o = 0
    elif link == 113:                  # Linux SLL
        o = 16
    elif link == 276:                  # Linux SLL2
        o = 20
    else:
        return None
    if len(p) < o + 20 or (p[o] >> 4) != 4:
        return None
    ihl = (p[o] & 0x0F) * 4
    if p[o + 9] != 6:
        return None
    t = o + ihl
    if len(p) < t + 20:
        return None
    src = ".".join(str(x) for x in p[o + 12:o + 16])
    dst = ".".join(str(x) for x in p[o + 16:o + 20])
    sp = (p[t] << 8) | p[t + 1]
    dp = (p[t + 2] << 8) | p[t + 3]
    dof = ((p[t + 12] >> 4) & 0x0F) * 4
    seq = struct.unpack(">I", p[t + 4:t + 8])[0]
    payload = p[t + dof:]
    if not payload:
        return None
    return (src, sp, dst, dp, seq, payload)


def _pcapng(data):
    off, link, out = 0, None, []
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, off)
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001 and len(body) >= 2:        # IDB
            link = struct.unpack_from("<H", body, 0)[0]
        elif btype == 0x00000006 and len(body) >= 20:     # EPB
            caplen = struct.unpack_from("<I", body, 12)[0]
            r = _extract_tcp(body[20:20 + caplen], link)
            if r:
                out.append(r)
        elif btype == 0x00000002 and len(body) > 4:       # SPB
            r = _extract_tcp(body[4:], link)
            if r:
                out.append(r)
        off += blen
    return out


def read(path):
    data = open(path, "rb").read()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return _pcapng(data)
    m = data[:4]
    if m in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif m in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        raise ValueError("unknown magic " + m.hex())
    link = struct.unpack_from(e + "I", data, 20)[0]
    off, out = 24, []
    while off + 16 <= len(data):
        incl = struct.unpack_from(e + "I", data, off + 8)[0]
        if off + 16 + incl > len(data):
            break
        r = _extract_tcp(data[off + 16:off + 16 + incl], link)
        if r:
            out.append(r)
        off += 16 + incl
    return out


def probe(path):
    data = open(path, "rb").read()
    m = data[:4]
    kind = "pcapng" if m == b"\x0a\x0d\x0d\x0a" else "pcap"
    link = None
    if kind == "pcap":
        e = "<" if m in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        link = struct.unpack_from(e + "I", data, 20)[0]
    print(f"{path}")
    print(f"  size={len(data)}  magic={m.hex()}  kind={kind}  linktype={link}")
    try:
        pkts = read(path)
    except Exception as ex:
        print(f"  read failed: {ex}")
        return
    print(f"  tcp packets with payload: {len(pkts)}")
    if pkts:
        s = pkts[0]
        print(f"  first: {s[0]}:{s[1]} -> {s[2]}:{s[3]} seq={s[4]} len={len(s[5])}")
        print(f"  ports seen: {sorted({x[1] for x in pkts} | {x[3] for x in pkts})}")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        probe(p)
''')

src = open("harness/extract.py", encoding="utf-8").read()
if "import pcapread" not in src:
    src = src.replace(
        "from collections import defaultdict",
        "from collections import defaultdict\nimport os as _os, sys as _sys\n_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))\ntry:\n    import pcapread\nexcept ImportError:\n    pcapread = None")
    a = src.index("def _read_pcap_pure(")
    z = src.index("def _concat(")
    src = src[:a] + '''def _read_pcap_pure(path):
    return pcapread.read(path)


''' + src[z:]
    src = src.replace('ap.add_argument("--selftest", action="store_true")',
                      'ap.add_argument("--selftest", action="store_true")\n    ap.add_argument("--probe", action="store_true")')
    src = src.replace("    if a.selftest:\n        return selftest()",
                      "    if a.selftest:\n        return selftest()\n    if a.probe:\n        pcapread.probe(a.pcap)\n        return 0")
    open("harness/extract.py", "w", encoding="utf-8", newline="\n").write(src)
    print("  patched harness/extract.py")

sh = open("run.sh", encoding="utf-8").read()
if "--probe" not in sh:
    sh = sh.replace('hdr "capture runner"',
                    'hdr "capture probe"\nfor f in caps/*.pcap; do python3 harness/extract.py --probe "$f"; done '
                    '2>&1 | tee results/probe.txt\n\nhdr "capture runner"')
    open("run.sh", "w", encoding="utf-8", newline="\n").write(sh)
    print("  extended run.sh")

print("\ndone.  run:")
print("  python3 harness/pcapread.py caps/*.pcap")
print("  python3 harness/extract.py --probe caps/reverse_level3_http_port_80.pcap")
print("  export GH_PAT=<token> && ./run.sh")