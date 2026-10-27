#!/usr/bin/env python3
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
