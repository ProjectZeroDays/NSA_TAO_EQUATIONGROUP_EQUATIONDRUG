NATIONAL SECURITY AGENCY - EQUATIONGROUP - EQUATIONDRUG

Parity reimplementation and protocol reconstruction of the Equation Group's
post-exploitation toolkit — the PeddleCheap (Pc) implant and its Listening Post
wire protocol, the RC5/AES configuration crypto, and the EquationDrug
ordinal-only plugin host — plus a pcap/log analysis harness validated against
the leak's own artifacts.

    NSA TAO  ·  Tailored Access Operations  ·  Equation Group

---

## Provenance

Nothing is inferred. Every layout is re-derived from a primary source:

| Source | Pins down |
|---|---|
| `dp_decrypt.py` (johnbergbom/PeddleCheap) | frame layouts, both directions, byte for byte |
| DanderSpritz LP XML log | a reference parser naming the blob fields |
| `Pc_Listen_Command.xml` | the authoritative `pc_listen` command surface |
| `pc2_2/payload/config.py` | the `PCHEAP_CONFIG_*` flag vocabulary |
| `649/EquationDrug` | leaked binaries, plugin ABI, artifact map |

## Protocol

Frame headers **differ by direction**. A logged `DataSent: 24` is eight bytes of
header plus one sixteen-byte AES block.

Implant to LP (POST body), 8-byte header:

| off | field |
|---|---|
| +0 | `clear_text_length` (u32 BE) |
| +4 | `length2` (u8) |
| +5 | `symm_encr_used` (u8) |
| +6 | reserved (u16) |
| +8 | ciphertext |

LP to implant (200 body, first sub-message), 16-byte header:

| off | field |
|---|---|
| +0 | reserved (u32) |
| +4 | `seq` (u32 LE) |
| +8 | `clear_text_length` (u32 BE) |
| +12 | `length2` (u8) |
| +13 | `symm_encr_used` (u8) |
| +14 | reserved (u16) |
| +16 | ciphertext |

Later sub-messages in a body reuse the implant-side header.

Handshake: initial contact, RSA magic number, RSA-encrypted session key and
platform metadata, OS version check, command poll, PayloadInfo run type plus
File/Library info, export name, executable stream.

Crypto: raw RSA-2048 (e = 65537, unpadded); AES-128-CBC with
`IV_next = last ciphertext block`.

## pc_listen surface

| option | values |
|---|---|
| `run` | runType: egg=1, memlib=2, filelib=3, exe=4 |
| `tcp` / `http` | protocol 0 / 1 |
| `connectPrefix` | default `TlEo:` |
| `maxConnectBytes` | default 12288 |

`TlEo:` is a configurable connect prefix passed positionally, not a codename.

## File/Library blob (36 bytes)

| off | field | status |
|---|---|---|
| +16 | library type | candidate |
| +20 | `0xdcce0000` | open |
| +24 | `sendSize` (u32 BE) | confirmed |
| +28 | `checksum` (u16 LE) | confirmed |
| +30 | `runType` | candidate |
| +32 | RunLibrary flags (u16 BE) | confirmed |

`origSize` is absent from the blob; it comes from the compressed stream.

## EquationDrug

- ordinal-only plugin ABI: exports @1-@4, names stripped, shared with DanderSpritz
- plugin IDs even and >= 0x8000; registry root `MemSubSys\1`
- config records `[type u16][size u16][value]`; RC5-family cipher
- artifacts: mutex `{01C482BA-...}`, event `{D0385CB7-...}`, log `~yh56816.tmp`

## Layout

    include/ src/ def/ plugins/   C implementation
    harness/                      pcap and log analysis, validation, runner
    tests/                        RFC 2040 / FIPS-197 vector gates
    docs/                         protocol reference, RE notes
    results/                      generated output, committed by run.sh

## Usage

    export GH_PAT=<classic token with repo scope>
    ./run.sh

Fetches inputs, runs the harness, writes `results/`, creates the public repo if
absent, pushes, and prints OK/FAIL per step. No dependencies beyond `git`,
`curl` and `python3` — the pcap reader is pure Python.

## Validation

    python3 harness/extract.py --selftest
    python3 harness/verify.py   --selftest
    make test

`run_all.py` exits non-zero if any capture yields no frames.

## Sources

- https://github.com/johnbergbom/PeddleCheap
- https://github.com/francisck/DanderSpritz_docs
- https://github.com/649/EquationDrug
