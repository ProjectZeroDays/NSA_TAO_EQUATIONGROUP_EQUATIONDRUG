#!/usr/bin/env python3
"""dllflags.py - recover PCHEAP flag vocabulary from a PE; --xref gives the bit."""
import re, struct, subprocess, sys

HUNT = re.compile(r"PCHEAP|memlib|filelib|runType|RunLibrary|TlEo|connectPrefix|"
                  r"LIBFLAG|LIB_FLAG|Pc_listen|Pc_connect|PcStatus|InjectDll|"
                  r"PayloadInfo|LibraryInfo|FileInfo|Export|EggPayloadInfo", re.I)
MACH = {0x14c: "i386", 0x8664: "x64", 0x1c0: "arm", 0xaa64: "arm64"}
# immediate anywhere on the line, short form only (excludes absolute addresses)
IMM = re.compile(r"\$0x([0-9a-f]{1,4})\b")


def parse_pe(b):
    if b[:2] != b"MZ":
        return None
    e = struct.unpack_from("<I", b, 0x3c)[0]
    if b[e:e+2] != b"PE":
        return None
    machine, nsec = struct.unpack_from("<HH", b, e + 4)
    optsz = struct.unpack_from("<H", b, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", b, opt)[0]
    wide = magic == 0x20b
    base = struct.unpack_from("<Q" if wide else "<I", b, opt + (24 if wide else 28))[0]
    secs = []
    for i in range(nsec):
        s = opt + optsz + i * 40
        if s + 40 > len(b):
            break
        secs.append({"name": b[s:s+8].rstrip(b"\0").decode("latin1"),
                     **dict(zip(("vsize", "va", "raw", "praw"),
                                struct.unpack_from("<IIII", b, s + 8)))})
    dd = opt + (112 if wide else 96)
    return {"machine": machine, "magic": magic, "base": base, "secs": secs,
            "dirs": [struct.unpack_from("<II", b, dd + i * 8) for i in range(16)]}


def off2va(pe, off):
    for s in pe["secs"]:
        if s["praw"] <= off < s["praw"] + s["raw"]:
            return pe["base"] + s["va"] + (off - s["praw"])
    return -1


def rva2off(pe, rva):
    for s in pe["secs"]:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["raw"]):
            return s["praw"] + (rva - s["va"])
    return -1


def cstr(b, o, n=300):
    end = b.find(b"\0", o, o + n)
    return b[o:end if end > 0 else o + n].decode("latin1", "replace")


def exports(pe, b):
    rva = pe["dirs"][0][0]
    if not rva:
        return []
    off = rva2off(pe, rva)
    if off < 0:
        return []
    n = struct.unpack_from("<I", b, off + 24)[0]
    nr = rva2off(pe, struct.unpack_from("<I", b, off + 32)[0])
    if nr < 0:
        return []
    out = []
    for i in range(min(n, 8192)):
        o = rva2off(pe, struct.unpack_from("<I", b, nr + i * 4)[0])
        if o >= 0:
            out.append(cstr(b, o))
    return out


def vocab(b):
    a, w = [], []
    for m in re.finditer(rb"[\x20-\x7e]{5,}", b):
        s = m.group().decode("latin1")
        if HUNT.search(s):
            a.append((m.start(), s))
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", b):
        s = m.group().decode("utf-16le", "replace")
        if HUNT.search(s):
            w.append((m.start(), s))
    return a, w


def xref(path, targets):
    try:
        dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", path],
                             capture_output=True, text=True).stdout.splitlines()
    except FileNotFoundError:
        print("   (objdump missing - install binutils for --xref)")
        return
    for name, va in targets:
        needle = f"0x{va:x}"
        poss = [i for i, l in enumerate(dis) if needle in l]
        if not poss:
            print(f"  [xref] {name:<46} va={needle:<12} no code reference")
            continue
        for p in poss[:1]:
            lo, hi = max(0, p - 30), min(len(dis), p + 30)
            cands = []
            for i in range(lo, hi):
                l = dis[i]
                for m in IMM.finditer(l):
                    v = int(m.group(1), 16)
                    if 0 < v <= 0x1000 and (v & (v - 1)) == 0:
                        cands.append((abs(i - p), hex(v), l.strip()))
            cands.sort(key=lambda c: c[0])
            print(f"  [xref] {name:<46} va={needle:<12} "
                  f"nearest single-bit immediates: {[c[1] for c in cands[:6]] or 'none'}")
            for d, v, l in cands[:4]:
                print(f"         d={d:<3} {v:<7} {l[:84]}")
            print(f"         ref: {dis[p].strip()[:84]}")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[-1]
    b = open(path, "rb").read()
    print(f"== {path}  ({len(b):,} bytes)")
    pe = parse_pe(b)
    if not pe:
        print("   not a PE")
        return 1
    print(f"   machine={MACH.get(pe['machine'], hex(pe['machine']))}  "
          f"pe={'PE32+' if pe['magic'] == 0x20b else 'PE32'}  base=0x{pe['base']:x}  "
          f"sections={len(pe['secs'])}")
    ex = exports(pe, b)
    if ex:
        pc = [n for n in ex if re.match(r"^(Pc|Peddle|Inject|RunLib|Status|Listen|Connect)", n, re.I)]
        print(f"   exports ({len(ex)}): " + (", ".join(pc) if pc else ", ".join(ex[:40])))
    else:
        print("   exports: none / ordinal-only")
    a, w = vocab(b)
    print(f"   vocabulary hits: {len(a)} ascii, {len(w)} wide")
    seen, targets = set(), []
    for o, s in a[:80]:
        if s in seen:
            continue
        seen.add(s)
        va = off2va(pe, o)
        print(f"     0x{o:06x}  va=0x{va:x}  {s}")
        if va > 0:
            targets.append((s, va))
    for o, s in w[:40]:
        if s in seen:
            continue
        seen.add(s)
        va = off2va(pe, o)
        print(f"     [wide] 0x{o:06x}  va=0x{va:x}  {s}")
        if va > 0:
            targets.append((s, va))
    if "--xref" in argv and targets:
        print("\n-- xref / single-bit immediate scan --")
        xref(path, targets)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
