#!/usr/bin/env python3
"""mock_lp.py - minimal Listening Post that drives pc_handshake and asserts frame framing.

It never decrypts (no private key), so it validates header shape, clear/pad
arithmetic and sub-message header switching, and replies with encr=0 so the
implant's receive path copies through verbatim. Framing errors fail the run.
"""
import argparse, json, os, socket, struct, sys, threading, time

HDR_IMPLANT, HDR_LP = 8, 16
BLOB = bytes.fromhex(
    "00" * 16 + "00000003" + "dcce0000" + "00028af4" + "205d" + "0100" + "0008" + "0000")


def lp_hdr(clear, length2, encr, seq):
    """16-byte LP header: reserved u32 LE + seq u32 LE + clear u32 BE + len2 u8 + encr u8 + reserved u16."""
    return (struct.pack("<I", 0) + struct.pack("<I", seq) + struct.pack(">I", clear)
            + bytes([length2, encr, 0, 0]))


def impl_hdr(clear, length2, encr):
    """8-byte implant header: clear u32 BE + len2 u8 + encr u8 + reserved u16."""
    return struct.pack(">I", clear) + bytes([length2, encr, 0, 0])


def resp_http(body):
    return (f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n"
            "Connection: Keep-Alive\r\n\r\n").encode() + body


# Step definitions: (clear, length2, encr, body_builder)
# step 0: connect-prefix frame, clear=4
# step 1: RSA-encrypted hello reply, clear=280
# step 2: blob frame, clear=4 + sub-message with BLOB
# step 3: export ack, clear=4
# step 4: executable stream frames + zero-length terminator
STEPS = [
    (4, 0, 0, lp_hdr(4, 0, 0, 0) + b"\x11\x22\x33\x44"),
    (280, 8, 1, lp_hdr(4, 0, 0, 1) + b"\x00" * 4),
    (4, 12, 1, lp_hdr(4, 0, 0, 2) + b"\x00" * 4 + impl_hdr(36, 0, 0) + BLOB),
    (4, 12, 1, lp_hdr(4, 0, 0, 3) + b"\x00" * 4),
    (4, 12, 1, _build_exe_stream()),
]


def _build_exe_stream():
    body = b""
    FRAME = 4096
    for i in range(3):
        h = lp_hdr(FRAME, 0, 0, i) if i == 0 else impl_hdr(FRAME, 0, 0)
        body += h + bytes([0xA0 + i]) * FRAME
    body += impl_hdr(0, 0, 0)  # zero-length terminator
    return body


def read_request(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            raise IOError("connection closed before headers")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    n = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            n = int(line.split(b":")[1])
    while len(rest) < n:
        chunk = conn.recv(4096)
        if not chunk:
            raise IOError("connection closed mid-body")
        rest += chunk
    return head.decode("latin-1"), rest[:n]


def check(head, body, idx):
    clear, pad, encr = STEPS[idx][0], STEPS[idx][1], STEPS[idx][2]
    errs = []
    if "tleo:" not in head.lower():
        errs.append(f"step{idx}: connect-prefix header missing")
    if "user-agent:" not in head.lower():
        errs.append(f"step{idx}: user-agent header missing")
    if len(body) < HDR_IMPLANT:
        errs.append(f"step{idx}: body {len(body)}B shorter than a header")
        return errs
    got_clear = struct.unpack_from(">I", body, 0)[0]
    got_pad, got_encr = body[4], body[5]
    if got_clear != clear:
        errs.append(f"step{idx}: clear {got_clear} != {clear}")
    if got_pad != pad:
        errs.append(f"step{idx}: pad {got_pad} != {pad}")
    if got_encr != encr:
        errs.append(f"step{idx}: encr {got_encr} != {encr}")
    if encr and not (1 <= got_pad <= 16):
        errs.append(f"step{idx}: pad {got_pad} outside 1..16 for an encrypted frame")
    if len(body) != HDR_IMPLANT + got_clear + got_pad:
        errs.append(f"step{idx}: body {len(body)}B != 8+{got_clear}+{got_pad}")
    return errs


def handle_conn(conn, addr, step_idx, port_file, errs, lock):
    try:
        head, body = read_request(conn)
        with lock:
            step_errs = check(head, body, step_idx)
            if step_errs:
                errs.extend(step_errs)
                print(f"step{step_idx}: FAIL")
                for e in step_errs:
                    print(f"  {e}")
            else:
                print(f"step{step_idx}: OK")
        # Reply with the configured response for this step
        clear, pad, encr, resp_body = STEPS[step_idx]
        resp = resp_http(resp_body)
        conn.sendall(resp)
    except Exception as e:
        with lock:
            errs.append(f"step{step_idx}: exception {e}")
            print(f"step{step_idx}: EXCEPTION {e}")
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-file", required=True)
    ap.add_argument("--timeout", type=float, default=20.0)
    a = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(a.timeout)
    open(a.port_file, "w").write(str(srv.getsockname()[1]))

    errs = []
    lock = threading.Lock()
    threads = []

    try:
        for idx in range(len(STEPS)):
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                errs.append(f"step{idx}: timed out waiting for connection")
                print(f"step{idx}: TIMEOUT")
                break
            t = threading.Thread(target=handle_conn, args=(conn, addr, idx,
                                                           a.port_file, errs, lock),
                                 daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=a.timeout)
    finally:
        srv.close()

    if errs:
        print(f"\nmock_lp: FAIL ({len(errs)} error(s))")
        for e in errs:
            print(f"  {e}")
        return 1
    print(f"\nmock_lp: OK ({len(STEPS)} steps validated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())