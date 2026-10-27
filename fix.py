#!/usr/bin/env python3
"""fix.py - rewrite the three files with the corrected versions."""
import os

FILES = {}

FILES["harness/dllflags.py"] = r'''
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
'''

FILES["run.sh"] = r'''
#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"

PAT="${GH_PAT:-}"
REPO="${GH_REPO:-NSA_TAO_EQUATIONDRUGS}"
BRANCH="${BRANCH:-main}"
API=https://api.github.com
PC=https://raw.githubusercontent.com/johnbergbom/PeddleCheap/master
DS=https://raw.githubusercontent.com/francisck/DanderSpritz_docs/master

ok(){  printf '\033[32m[ OK ]\033[0m %s\n' "$*"; }
bad(){ printf '\033[31m[FAIL]\033[0m %s\n' "$*"; }
inf(){ printf '\033[36m[ .. ]\033[0m %s\n' "$*"; }
hdr(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

for t in git curl python3; do
  command -v "$t" >/dev/null || { bad "missing dependency: $t"; exit 1; }
done

hdr "fetch inputs"
mkdir -p caps bins results
for f in forward_level3_tcp_port_1163.pcap forward_level4_tcp_port_1167.pcap \
         reverse_level3_http_port_80.pcap reverse_level3_http_port_443.pcap \
         reverse_level3_tcp_port_53.pcap PeddleCheap_Lp.dll DszLpCore.exe \
         00041-pc_listen_2017_10_16_09h37m12s.966.xml; do
  [ -s "caps/$f" ] && continue
  curl -fsSL -o "caps/$f" "$PC/$f" && ok "caps/$f" || bad "caps/$f"
done
curl -fsSL -o bins/PCConfig.exe "$DS/Pc2.2/Tools/i386-winnt/PCConfig.exe" \
  && ok "bins/PCConfig.exe" || bad "bins/PCConfig.exe"

hdr "selftests"
{ python3 harness/extract.py --selftest
  python3 harness/verify.py   --selftest
  python3 harness/diffblob.py --selftest ; } 2>&1 | tee results/selftest.txt

hdr "capture runner"
python3 harness/run_all.py caps 2>&1 | tee results/run_all.txt
python3 harness/run_all.py caps --json > results/run_all.json 2>/dev/null || true

hdr "binary vocabulary and xref"
for b in bins/PCConfig.exe caps/PeddleCheap_Lp.dll; do
  [ -f "$b" ] || continue
  echo "===== $b ====="
  python3 harness/dllflags.py "$b" 2>&1
  echo "----- xref -----"
  python3 harness/dllflags.py --xref "$b" 2>&1
  echo
done | tee results/dllflags.txt

hdr "log parser"
[ -f caps/00041-pc_listen_2017_10_16_09h37m12s.966.xml ] && \
  python3 harness/log_parse.py caps/00041-pc_listen_2017_10_16_09h37m12s.966.xml \
  > results/log_parse.txt 2>&1 && ok "log parsed" || bad "log parse"

hdr "report"
{
  echo "# parity report"
  echo
  echo "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(uname -srm)"
  echo
  for f in selftest run_all dllflags log_parse; do
    echo "## $f"; echo '```'
    head -c 30000 "results/$f.txt" 2>/dev/null || echo "(missing)"
    echo '```'; echo
  done
} > results/REPORT.md
ok "results/REPORT.md"

if [ -z "$PAT" ]; then
  bad "GH_PAT not set, skipping publish"; exit 0
fi

hdr "publish"
resp=$(curl -sS -H "Authorization: Bearer $PAT" -H "Accept: application/vnd.github+json" "$API/user")
OWNER=$(printf '%s' "$resp" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("login",""))
except Exception: print("")' 2>/dev/null)
if [ -z "$OWNER" ]; then
  bad "PAT rejected. GitHub said:"
  printf '  %s\n' "$(printf '%s' "$resp" | head -c 300)"
  echo "  check: not expired, classic token with 'repo' scope, no trailing whitespace"
  exit 1
fi
ok "authenticated as $OWNER"

if curl -fsSL -H "Authorization: Bearer $PAT" "$API/repos/$OWNER/$REPO" >/dev/null 2>&1; then
  inf "repo $OWNER/$REPO exists"
else
  curl -fsSL -X POST -H "Authorization: Bearer $PAT" -H "Accept: application/vnd.github+json" \
    "$API/user/repos" -d "{\"name\":\"$REPO\",\"private\":false,\"auto_init\":false}" >/dev/null \
    && ok "created public repo $OWNER/$REPO" || { bad "repo creation failed"; exit 1; }
fi

[ -d .git ] || git init -q -b "$BRANCH"
git config user.name  "${GIT_NAME:-$OWNER}"
git config user.email "${GIT_EMAIL:-$OWNER@users.noreply.github.com}"
git remote remove origin 2>/dev/null || true
git remote add origin "https://$OWNER:$PAT@github.com/$OWNER/$REPO.git"
git add -A && git add -f results
git commit -q -m "results: $(date -u +%Y-%m-%dT%H:%M:%SZ)" || inf "nothing to commit"

if git push -u origin "$BRANCH" >/dev/null 2>&1; then
  ok "pushed to $OWNER/$REPO"
  echo
  echo "REPORT: https://raw.githubusercontent.com/$OWNER/$REPO/$BRANCH/results/REPORT.md"
else
  bad "push failed"
  exit 1
fi
'''


def patch_extract(path):
    src = open(path, encoding="utf-8").read()
    old_start = src.index("def parse_frames(")
    old_end = src.index("def pick_direction(")
    new = '''def parse_frames(buf, direction, transport):
    """First frame of an LP->implant body carries the 16-byte header; every
    later sub-message reuses the 8-byte implant-side header."""
    frames, off, resync, first = [], 0, 0, True
    while True:
        hlen = HDR_IMPLANT if (direction == "implant->lp" or not first) else HDR_LP
        if off + hlen > len(buf):
            break
        if direction == "implant->lp":
            clear = struct.unpack_from(">I", buf, off)[0]
            length2, encr, seq = buf[off + 4], buf[off + 5], None
        else:
            seq = struct.unpack_from("<I", buf, off + 4)[0]
            clear = struct.unpack_from(">I", buf, off + 8)[0]
            length2, encr = buf[off + 12], buf[off + 13]
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


'''
    open(path, "w", encoding="utf-8", newline="\n").write(src[:old_start] + new + src[old_end:])


def main():
    for rel, body in FILES.items():
        os.makedirs(os.path.dirname(rel) or ".", exist_ok=True)
        with open(rel, "w", encoding="utf-8", newline="\n") as f:
            f.write(body.lstrip("\n"))
        if rel.endswith(".sh"):
            os.chmod(rel, 0o755)
        print(f"  wrote {rel}")
    patch_extract("harness/extract.py")
    print("  patched harness/extract.py")
    print("\ndone. now:  ./run.sh")


if __name__ == "__main__":
    main()