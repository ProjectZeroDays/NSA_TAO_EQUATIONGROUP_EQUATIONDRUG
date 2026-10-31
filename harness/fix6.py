#!/usr/bin/env python3
"""fix6.py - stop pcapread emitting Ethernet padding as TCP payload.

Two layers:
  1. hygiene  - clamp payload slice with IP total-length field
  2. guarantee - normalise read(): drop all-NUL stubs, keep longest payload
    per (5-tuple, seq)
"""
import os, re, shutil, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
P = "harness/pcapread.py"
BAK = P + ".bak"

shutil.copyfile(P, BAK)
s = open(P).read()
shim_ready = "def _read_impl(" in s
if not shim_ready:
    s = s.replace("def read(", "def _read_impl(", 1)

_NUL6 = b"\x00" * 6


def _normalise(rows):
    best, order = {}, []
    for src, sp, dst, dp, seq, pay in rows:
        if len(pay) <= 6 and pay == _NUL6[:len(pay)]:
            continue
        k = (src, sp, dst, dp, seq)
        if k not in best:
            best[k] = pay
            order.append(k)
        elif len(pay) > len(best[k]):
            best[k] = pay
    return [(k[0], k[1], k[2], k[3], k[4], best[k]) for k in order]


SHIM = '''
_NUL6 = b"\\x00" * 6


def _normalise(rows):
    best, order = {}, []
    for src, sp, dst, dp, seq, pay in rows:
        if len(pay) <= 6 and pay == _NUL6[:len(pay)]:
            continue
        k = (src, sp, dst, dp, seq)
        if k not in best:
            best[k] = pay
            order.append(k)
        elif len(pay) > len(best[k]):
            best[k] = pay
    return [(k[0], k[1], k[2], k[3], k[4], best[k]) for k in order]


def read(path, *a, **kw):
    return _normalise(_read_impl(path, *a, **kw))
'''

if "def _normalise(" not in s:
    s = s.rstrip("\n") + "\n" + SHIM

def try_layer1(text):
    LAYER1 = [
        (re.compile(r"(?m)^(\s*)(payload|pay)\s*=\s*(tcp\[[^\n]+)\$"),
         r"\1\2 = (\3)[:max(0, tot - ihl - doff)]"),
    ]
    for rx, rep in LAYER1:
        new, n = rx.subn(rep, text)
        if n:
            try:
                compile(new, P, "exec")
                print("layer 1: clamped %d payload slice(s)" % n)
                return new
            except SyntaxError:
                pass
    print("layer 1: source shape not recognised (relying on layer 2 only)")
    return text


def verify(verbose=True):
    sys.path.insert(0, os.path.join(ROOT, "harness"))
    for m in ("pcapread", "extract"):
        sys.modules.pop(m, None)
    import pcapread, extract
    path = "caps/reverse_level3_http_port_80.pcap"
    streams = extract.tcp_streams(path)
    bad = [(k, b[:12].hex()) for k, b in streams.items()
           if b[:6] == _NUL6]
    http = sum(1 for b in streams.values()
               if extract.classify(b)[1] == "http")
    frames = len(extract.extract(path))
    if verbose:
        print("verify: streams=%d  nul-stub heads=%d  http=%d  frames=%d"
              % (len(streams), len(bad), http, frames))
        for k, h in bad[:5]:
            print("   still bad:", k, h)
    return not bad and http > 0


patched = try_layer1(s)
open(P, "w").write(patched)
ok = verify()
print("[OK] pcapread patched, backup at %s" % BAK if ok else "[FAIL] inspect %s" % BAK)
print("[diag] fix6 applied to harness/pcapread.py")
