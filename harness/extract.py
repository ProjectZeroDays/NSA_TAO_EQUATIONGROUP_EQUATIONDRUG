#!/usr/bin/env python3
"""extract.py - PeddleCheap frame extractor (HTTP + raw TCP), dependency-free."""
import argparse, json, re, struct, sys
from collections import defaultdict
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
try:
    import pcapread
except ImportError:
    pcapread = None

try:
    from scapy.all import rdpcap, IP, TCP
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

HDR_IMPLANT, HDR_LP, BLOCK = 8, 16, 16
MAX_CLEAR = 0x100000
MAX_PAD = 32
RESYNC_CAP = 1 << 18


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
    return pcapread.read(path)


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


HTTP_ANCHORS = (b"POST / HTTP/1.", b"GET / HTTP/1.")


def find_http_start(buf):
    """Streams begin mid-conversation or carry SMB noise; anchor on a request line."""
    best = -1
    for m in HTTP_ANCHORS:
        i = buf.find(m)
        if i >= 0 and (best < 0 or i < best):
            best = i
    return best


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
    Only the first frame of an LP->implant body carries the 16-byte header.

    A candidate that overruns the buffer resyncs one byte forward rather than
    aborting, so a stream with a non-frame prefix (SMB, TLS, mid-body start)
    still yields frames further in.
    """
    frames, off, first, run = [], 0, True, 0
    while off + HDR_IMPLANT <= len(buf):
        hlen = HDR_LP if (direction != "implant->lp" and first16 and first) else HDR_IMPLANT
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
        end = off + hlen + plen
        ok = (plen > 0 and plen <= MAX_CLEAR and end <= len(buf)
              and length2 <= MAX_PAD and (encr in (0, 1)))
        if ok:
            frames.append(Frame(transport=transport, direction=direction, seq=seq,
                                clear_len=clear, length2=length2, encr=encr,
                                ciphertext=buf[off + hlen:end]))
            off = end
            first = False
            run = 0
        else:
            off += 1
            run += 1
            if run > RESYNC_CAP:
                break
    return frames, run


def pick_direction(buf, transport):
    """Score on frame count first, resync count second; require at least one frame."""
    best, best_frames, best_score = None, [], None
    for d in ("implant->lp", "lp->implant"):
        for f16 in (True, False):
            fr, rs = parse_frames(buf, d, transport, f16)
            if not fr:
                continue
            score = len(fr) * 1024 - rs
            if best_score is None or score > best_score:
                best, best_frames, best_score = d, fr, score
    return best, best_frames, best_score


def extract_stream(buf):
    a = find_http_start(buf)
    if a >= 0:
        buf = buf[a:]
        direction, _ = classify(buf)
        body = http_body(buf)
        if not body:
            return []
        frames, _ = parse_frames(body, direction, "http")
        return frames
    _, frames, _ = pick_direction(buf, "tcp")
    return frames


def extract(pcap, ports=None):
    records = []
    for key, buf in tcp_streams(pcap).items():
        if ports and key[1] not in ports and key[3] not in ports:
            continue
        records.extend(extract_stream(buf))
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
    # regression: 4096 bytes of SMB noise then a valid frame must still parse
    noise = bytes((i * 7 + 3) & 0xFF for i in range(4096))
    fr4, rs4 = parse_frames(noise + hdr + b"\xAA" * 16, "implant->lp", "tcp")
    assert len(fr4) >= 1 and fr4[-1].clear_len == 4, (len(fr4), rs4)
    # regression: garbage with an overrunning length must not abort the scan
    bad = b"\x00\x0f\xff\xff" + bytes([0, 1, 0, 0])
    fr5, _ = parse_frames(bad + hdr + b"\xAA" * 16, "implant->lp", "tcp")
    assert len(fr5) == 1 and fr5[0].clear_len == 4
    print("selftest: OK (5 frame shapes, resync after noise and overrun)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--port", type=int, action="append", default=[])
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.probe:
        pcapread.probe(a.pcap)
        return 0
    recs = extract(a.pcap, set(a.port) or None)
    if a.json:
        print(json.dumps([r.as_dict() for r in recs], indent=2))
    else:
        for r in recs:
            print(f"{r.transport:5} {r.direction:11} seq={r.seq} clear={r.clear_len} "
                  f"len2={r.length2} encr={r.encr} ct={len(r.ciphertext)}B")
    print(f"-- {len(recs)} frames", file=sys.stderr)


if __name__ == "__main__":
    main()