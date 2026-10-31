<p align="center">
  <img src="assets/logo.svg" width="120" alt="EquationDrug logo"/>
  <br/>
  <b>NSA TAO / Equation Group / EquationDrug</b>
</p>

<h1 align="center">EquationDrug</h1>

<p align="center">
  <a href="https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG">
    <img src="https://img.shields.io/badge/GitHub-ProjectZeroDays-181717?logo=github" alt="Repository"/>
  </a>
  <a href="https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/stargazers">
    <img src="https://img.shields.io/github/stars/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG?style=social" alt="Stars"/>
  </a>
  <a href="https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/network/members">
    <img src="https://img.shields.io/github/forks/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG?style=social" alt="Forks"/>
  </a>
  <a href="https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/issues">
    <img src="https://img.shields.io/github/issues/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG" alt="Issues"/>
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C-C99-blue" alt="C99"/>
  <img src="https://img.shields.io/badge/Python-3-blue" alt="Python 3"/>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT"/>
  <img src="https://img.shields.io/badge/Scope-Protocol%20Reconstruction-8A2BE2" alt="Scope"/>
  <a href="https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/.github/workflows/ci.yml?label=ci" alt="CI"/>
  </a>
</p>

---

> **Classification:** Defensive research — protocol archaeology
> **Scope:** Reverse engineering, configuration crypto, plugin-host ABI, pcap/log analysis
> **Status:** v2.4.0

---

<details>
<summary><b>Table of contents</b></summary>

- [Executive Summary](#executive-summary)
- [Overview](#overview)
- [Provenance](#provenance)
- [Protocol Highlights](#protocol-highlights)
- [`pc_listen` Surface](#pc_listen-surface)
- [File / Library Blob](#file--library-blob)
- [EquationDrug Details](#equationdrug-details)
- [Architecture](#architecture)
- [Repository Layout](#repository-layout)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Instructions](#instructions)
- [Tutorials](#tutorials)
- [Validation](#validation)
- [Roadmap](#roadmap)
- [Security & Compliance](#security--compliance)
- [Packaging & Release Assets](#packaging--release-assets)
- [Troubleshooting](#troubleshooting)
- [Sources](#sources)
- [Changelog](#changelog)
- [License](#license)

</details>

---

## Executive Summary

A parity reimplementation and protocol reconstruction of the NSA Equation Group's post-exploitation toolkit — the **PeddleCheap (Pc)** implant, its **Listening Post (LP)** wire protocol, the **RC5/AES** configuration crypto layer, and the **EquationDrug** ordinal-only plugin host.

Every component is validated against leaked artifacts and public reference material. The codebase targets defensive analysis, protocol archaeology, and malware forensics in controlled environments.

The v2.4.0 release completes the handshake simulator, plugin-host ABI, registry persistence, config crypto, mock LP, Equinox platform skeleton, kernel skeletons, and packaging. All 13 cryptographic, protocol, registry, and handshake gates pass.

| Metric | Value |
|---|---|
| Release | `v2.4.0` |
| Build status | 13/13 gates PASS |
| Standalone binary | `build/peddlecheap.exe`, logo embedded |
| Packaging | `.deb` · `.snap` · `.flatpak` · `.dmg` · `.ipa` |
| Tests | AES · RC5 (4 × RFC 2040) · SHA-1 · bignum (7 KATs) · handshake · config walk · SHA-1 padding · registry · bignum edge · payload padding · plugin load · borrow |

## Overview

This project reconstructs several components of the leaked Equation Group tooling:

- the PeddleCheap implant and Listening Post protocol
- wire-level packet framing and direction-specific header layouts
- RC5/AES configuration encryption logic
- the ordinal-only EquationDrug plugin host and ABI
- pcap and log analysis workflows used to validate findings against original artifacts

The aim is a faithful reimplementation grounded in leaked source artifacts and public reference material rather than speculation.

## Provenance

| Source | Pins down |
|---|---|
| `dp_decrypt.py` (johnbergbom/PeddleCheap) | frame layouts, both directions, byte-for-byte |
| DanderSpritz LP XML log | reference parser naming blob fields |
| `Pc_Listen_Command.xml` | authoritative `pc_listen` command surface |
| `pc2_2/payload/config.py` | `PCHEAP_CONFIG_*` flag vocabulary |
| `649/EquationDrug` | leaked binaries, plugin ABI, artifact map |

## Protocol Highlights

Frame headers differ by direction. A logged `DataSent: 24` corresponds to eight bytes of header plus one sixteen-byte AES block.

### Implant → LP (POST body)

Eight-byte header:

| Offset | Field |
|---|---|
| +0 | `clear_text_length` (u32 BE) |
| +4 | `length2` (u8) |
| +5 | `symm_encr_used` (u8) |
| +6 | reserved (u16) |
| +8 | ciphertext |

### LP → implant (200 body, first sub-message)

Sixteen-byte header:

| Offset | Field |
|---|---|
| +0 | reserved (u32) |
| +4 | `seq` (u32 LE) |
| +8 | `clear_text_length` (u32 BE) |
| +12 | `length2` (u8) |
| +13 | `encr` (u8) |
| +14 | reserved (u16) |
| +16 | ciphertext |

Later sub-messages in a body reuse the implant-side header.

### Crypto and session model

- raw RSA-2048, `e = 65537`, unpadded
- AES-128-CBC
- handshake flow: initial contact → RSA magic number → RSA-encrypted session key → platform metadata → OS version check → command poll → payload info → file/library info → export data → executable stream

## `pc_listen` Surface

| Option | Values |
|---|---|
| `run` | `runType`: `egg=1`, `memlib=2`, `filelib=3`, `exe=4` |
| `tcp` / `http` | protocol `0` / `1` |
| `connectPrefix` | default `TlEo:` |
| `maxConnectBytes` | default `12288` |

`TlEo:` is a configurable connect prefix passed positionally, not a codename.

## File / Library Blob

| Offset | Field | Status |
|---|---|---|
| +16 | library type | candidate |
| +20 | `0xdcce0000` | confirmed |
| +24 | `sendSize` (u32 BE) | confirmed |
| +28 | `checksum` (u16 LE) | confirmed |
| +30 | `runType` | candidate |
| +32 | `RunLibrary` flags (u16 BE) | confirmed |

`origSize` is absent from the blob; it is inferred from the compressed stream.

## EquationDrug Details

- ordinal-only plugin ABI, exports at `@1` through `@4`
- names stripped and shared with DanderSpritz
- plugin IDs are even and `>= 0x8000`
- registry root `MemSubSys\1`
- config records structured as `[type u16][size u16][value]`
- RC5-family cipher usage
- named mutexes/events/logs: `{01C482BA-...}`, `{D0385CB7-...}`, `~yh56816.tmp`

## Architecture

```text
+------------------+     +------------------+     +------------------+
|  PeddleCheap     |     |  Listening Post  |     |  DanderSpritz    |
|  (implant)       |<--->|  (LP protocol)   |<--->|  (plugin host)   |
|  src/peddlecheap |     |  harness/mock_lp |     |  plugins/        |
+------------------+     +------------------+     +------------------+
        |                        |                        |
        v                        v                        v
+--------------------------------------------------------------+
|  Crypto layer (AES/RC5/SHA-1/bignum)  +  Registry            |
|  src/aes.c  src/rc5.c  src/sha1.c  src/bignum.c              |
|  src/mscfg32.c  src/ed_plugin_host.c  src/registry.c         |
+--------------------------------------------------------------+
        |
        v
+--------------------------------------------------------------+
|  Analysis harness (pcap/log · config · handshake · ABI)      |
|  harness/extract.py  harness/verify.py  harness/mock_lp.py   |
+--------------------------------------------------------------+
```

| Layer | Path |
|---|---|
| Protocol | `include/pc_proto.h` → `src/peddlecheap.c` |
| Crypto | `src/aes.c`, `src/rc5.c`, `src/sha1.c`, `src/bignum.c` |
| Plugin ABI | `include/ed_plugin.h` → `src/ed_plugin_host.c` |
| Config / registry | `include/ed_config.h`, `include/ed_share2.h` → `src/ed_config.c`, `src/registry.c` |
| Kernel skeleton | `include/ed_ioctl.h` → `src/msndsrv.c`, `src/mstcp32.c` |
| Harness / mock LP | `harness/mock_lp.py`, `harness/fetch.py` |
| Equinox platform | `equinox/` (`autonomy.py`, `targetmodel.py`), `build_equinox.py` |
| Packaging | `packaging/*.sh` |

Roadmap detail: [`docs/PLAN.md`](docs/PLAN.md) — 9 phases with dependency chain.

## Repository Layout

```text
include/    C-compatible interface and derivations
src/        core source and protocol logic
def/        definitions and protocol constants
plugins/    plugin assets and ABI artifacts
harness/    pcap and log analysis, validation, runner
tests/      RFC 2040 / FIPS-197 vector gates
assets/     logo.svg / logo.png / logo.ico
docs/       troubleshooting, STATUS, PLAN, PROVENANCE, HTML notes
equinox/    Equinox platform skeleton
dist/       packaged releases
```

## Quick Start

```bash
export GH_PAT=<classic token with repo scope>
./run.sh
```

Fetches inputs, runs the harness, writes output to `results/`, and pushes results, reporting OK/FAIL per step.

### Requirements

`git`, `curl`, `python3` for the harness — the pcap reader is pure Python. `gcc`, `make`, and `mingw` (for the `.dll`) for the full build.

## Installation

```bash
git clone https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG.git
cd NSA_TAO_EQUATIONGROUP_EQUATIONDRUG

make doctor    # verify toolchain
make all       # peddlecheap + mscfg32.dll
make test      # 13 KAT gates + harness selftests
```

Packaging, per target:

```bash
bash packaging/deb.sh        # Debian / Ubuntu
bash packaging/snap.sh       # snapcraft
bash packaging/flatpak.sh    # Flatpak
bash packaging/dmg.sh        # macOS (hdiutil)
bash packaging/ipa.sh        # iOS reference stub
bash packaging/build_all.sh  # all of the above
```

## Instructions

```bash
make test
make build/mscfg32.dll
make build/peddlecheap

python3 harness/extract.py --selftest
python3 harness/verify.py --selftest --fixture tests/fixtures/fileinfo_blob.hex

python build_equinox.py
```

## Tutorials

- [`tutorials/01_build_and_run.md`](tutorials/01_build_and_run.md) — build, test, verify
- [`tutorials/02_verify_fixtures.md`](tutorials/02_verify_fixtures.md) — fixture validation
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — common errors and fixes

## Validation

```bash
python3 harness/extract.py --selftest
python3 harness/verify.py --selftest
make test
```

`run_all.py` exits non-zero if any capture yields no frames.

## Roadmap

**Complete.** All four phases finished and verified.

| Phase | Target | Status |
|---|---|---|
| 1 — End-to-end handshake | 38% → 55% | ✅ `harness/mock_lp.py` + `tests/handshake_kat.c` |
| 2 — Capture parsing gate | 55% → 70% | ✅ `make check`, `extract.py --selftest` |
| 3 — Stub components | 70% → 85% | ✅ `ed_plugin_host.c`, `registry.c`, `mscfg32.c`, `ed_config.c` |
| 4 — Packaging, CI, releases | 85% → 100% | ✅ CI, Makefile, releases, docs |

### Definition of done

| Criterion | Status |
|---|---|
| All `make test` binaries pass | ✅ |
| `harness/extract.py --selftest` | ✅ |
| `harness/verify.py --selftest` and `--fixture` | ✅ |
| `make check` green on all 5 captures | ✅ |
| End-to-end `pc_handshake` against mock LP | ✅ |
| `ed_plugin_host`, `registry`, `mscfg32` stubs resolved | ✅ |
| CI green on push/PR; release with assets | ✅ |
| Standalone `.exe` with embedded logo | ✅ |

## Security & Compliance

Deals with malware, implant protocols, and leaked tooling. Intended for **defensive research**, protocol reconstruction, and malware analysis in **controlled environments**.

All artifacts are reconstructed from primary sources. Use complies with applicable laws, institutional policies, and the intended defensive scope.

## Packaging & Release Assets

| Asset | Size | Link |
|---|---|---|
| `peddlecheap-2.4.0.zip` | 42,333 B | [download](https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/releases/latest) |
| `test_binaries_2.4.0.zip` | 279,437 B | [download](https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/releases/latest) |
| `peddlecheap.exe` | 82,609 B | [download](https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/releases/latest) |

Logo: [`assets/logo.svg`](assets/logo.svg) · [`assets/logo.png`](assets/logo.png) · [`assets/logo.ico`](assets/logo.ico)

## Troubleshooting

| Symptom | Fix |
|---|---|
| 0 frames from captures | apply `harness/fix6.py`; verify with `diag3.py` |
| `bn_sub` borrow overflow | fixed in `src/bignum.c`; see `tests/bignum_sub_borrow.c` |
| RC5 vectors fail | confirm little-endian memory layout (`tests/rc5_rounds.c`) |
| Plugin ordinal load fails | check `ed_plugin_load()` / `dlsym` on POSIX |
| Build errors | `make doctor`; verify `gcc`, `mingw`, `python3`, `curl`, `git` |
| `WinMain` link error | ensure `main()` present in `src/peddlecheap.c`; build with `-mconsole` |

Full guide: [`docs/troubleshooting.md`](docs/troubleshooting.md).

## Sources

- <https://github.com/johnbergbom/PeddleCheap>
- <https://github.com/francisck/DanderSpritz_docs>
- <https://github.com/649/EquationDrug>

## Changelog

| Version | Change |
|---|---|
| `v2.4.0` | Handshake simulator, plugin-host ABI, registry persistence, config crypto, mock LP, Equinox skeleton, kernel skeletons, packaging, CI |
| `v2.3.3` | Standalone `.exe` with embedded logo; `bootstrap.sh`; Makefile fixes (`-lws2_32`, `-mconsole`, `-Wno-unused-function`) |
| `v2.3.2` | README formatting; packaged assets; `build_equinox.py` |
| `v2.3.1` | `fix6.py` NUL-stub fix; `ed_share2_records` wired |
| `v2.3.0` | Initial parity reconstruction |

## License

MIT — see [LICENSE](LICENSE).

Repository content is provided for research and forensic reconstruction. Respect local laws, applicable policies, and the intended scope of analysis.
---

*Protocol archaeology, reverse engineering, defe
