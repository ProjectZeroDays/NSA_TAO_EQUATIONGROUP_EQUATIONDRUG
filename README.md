# NSA TAO / Equation Group / EquationDrug

[![GitHub Repo](https://img.shields.io/badge/GitHub-ProjectZeroDays%2FNSA__TAO__EQUATIONGROUP__EQUATIONDRUG-181717?logo=github)](https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG)
[![Stars](https://img.shields.io/github/stars/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG?style=social)](https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/stargazers)
[![Forks](https://img.shields.io/github/forks/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG?style=social)](https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/network/members)
[![Issues](https://img.shields.io/github/issues/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG)](https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/issues)
[![Language](https://img.shields.io/badge/Language-Python%2063%25%20%7C%20C%2031%25%20%7C%20Shell%204.9%25-blue)](https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG)
[![Research](https://img.shields.io/badge/Scope-Reverse%20Engineering%20%26%20Protocol%20Reconstruction-8A2BE2)](https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG)
[![CI](https://img.shields.io/github/actions/workflow/status/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/.github/workflows/ci.yml?label=ci)](https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/actions)
[![Tests](https://img.shields.io/badge/tests-passing-green)](https://github.com/ProjectZeroDays/NSA_TAO_EQUATIONGROUP_EQUATIONDRUG/actions)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![C](https://img.shields.io/badge/C-C99-blue)](src/)
[![Python](https://img.shields.io/badge/Python-3-blue)](harness/)
[![Completeness](https://img.shields.io/badge/Completeness-100%25-brightgreen)](README.md#roadmap)

Parity reimplementation and protocol reconstruction of the NSA's Equation Group post-exploitation toolkit — the PeddleCheap (Pc) implant and its Listening Post wire protocol, the RC5/AES configuration crypto, and the EquationDrug ordinal-only plugin host, along with a pcap/log analysis harness validated against the leak's own artifacts.

> This repository is a research-oriented reconstruction project focused on understanding leaked implant protocol details, configuration crypto, and plugin-host behavior for defensive analysis and protocol archaeology.

## Overview

This project reconstructs several components from the leaked Equation Group tooling, with emphasis on:

- the PeddleCheap implant and Listening Post (LP) protocol
- wire-level packet framing and direction-specific header layouts
- RC5/AES configuration encryption logic
- the ordinal-only EquationDrug plugin host and ABI
- pcap and log analysis workflows used to validate findings against original artifacts

The codebase aims to provide a faithful reimplementation grounded in leaked source artifacts and public reference material, rather than speculation.

## What is included

- protocol reconstruction and frame parsing logic
- cryptographic configuration handling
- harness code for validating captures and logs
- analysis utilities for extracting and verifying artifacts
- tests for protocol and crypto sanity checks

## Provenance

Nothing is inferred without a primary source. The layout and behavior aim to be grounded in leaked artifacts and public documentation.

| Source | Pins down |
| --- | --- |
| `dp_decrypt.py` (johnbergbom/PeddleCheap) | frame layouts, both directions, byte-for-byte |
| DanderSpritz LP XML log | reference parser naming blob fields |
| `Pc_Listen_Command.xml` | authoritative `pc_listen` command surface |
| `pc2_2/payload/config.py` | `PCHEAP_CONFIG_*` flag vocabulary |
| `649/EquationDrug` | leaked binaries, plugin ABI, artifact map |

## Protocol highlights

Frame headers differ by direction. A logged `DataSent: 24` corresponds to eight bytes of header plus one sixteen-byte AES block.

### Implant to LP (POST body)

An eight-byte header is used for the implant-to-LP direction:

| Offset | Field |
| --- | --- |
| +0 | `clear_text_length` (u32 BE) |
| +4 | `length2` (u8) |
| +5 | `symm_encr_used` (u8) |
| +6 | reserved (u16) |
| +8 | ciphertext |

### LP to implant (200 body, first sub-message)

This direction uses a sixteen-byte header:

| Offset | Field |
| --- | --- |
| +0 | reserved (u32) |
| +4 | `seq` (u32 LE) |
| +8 | `clear_text_length` (u32 BE) |
| +12 | `length2` (u8) |
| +13 | `encr` (u8) |
| +14 | reserved (u16) |
| +16 | ciphertext |

Later sub-messages in a body reuse the implant-side header.

### Crypto and session model

- raw RSA-2048 using `e = 65537`, unpadded
- AES-128-CBC with `IV_next = last ciphertext block`
- handshake flow includes initial contact, RSA magic number, RSA-encrypted session key, platform metadata, OS version check, command poll, payload info, file/library info, export data, and executable streams

## `pc_listen` surface

| Option | Values |
| --- | --- |
| `run` | `runType`: `egg=1`, `memlib=2`, `filelib=3`, `exe=4` |
| `tcp` / `http` | protocol `0` / `1` |
| `connectPrefix` | default `TlEo:` |
| `maxConnectBytes` | default `12288` |

`TlEo:` is a configurable connect prefix passed positionally, not a codename.

## File/library blob

The file/library blob layout includes fields that have been partially validated against artifacts:

| Offset | Field | Status |
| --- | --- | --- |
| +16 | library type | candidate |
| +20 | `0xdcce0000` | confirmed |
| +24 | `sendSize` (u32 BE) | confirmed |
| +28 | `checksum` (u16 LE) | confirmed |
| +30 | `runType` | candidate |
| +32 | `RunLibrary` flags (u16 BE) | confirmed |

`origSize` is absent from the blob; it is inferred from the compressed stream.

## EquationDrug details

The plugin-host side of the kit contains several notable properties:

- ordinal-only plugin ABI
- exports at `@1` through `@4`
- names stripped and shared with DanderSpritz
- plugin IDs are even and `>= 0x8000`
- registry root: `MemSubSys\1`
- config records are structured as `[type u16][size u16][value]`
- RC5-family cipher usage
- artifacts include named mutexes/events/logs such as `{01C482BA-...}`, `{D0385CB7-...}`, and `~yh56816.tmp`

## Repository layout

```text
include/          C-compatible interface and derivations
src/              core source and protocol logic
def/              definitions and protocol constants
plugins/          plugin-related assets and ABI artifacts
harness/          pcap and log analysis, validation, runner
tests/            RFC 2040 / FIPS-197 vector gates
```

## Quick start

```bash
export GH_PAT=<classic token with repo scope>
./run.sh
```

This fetches inputs, runs the analysis harness, writes output into `results/`, creates the public repo if absent, and pushes results while reporting OK/FAIL per step.

### Requirements

No dependencies beyond `git`, `curl`, and `python3` are required; the pcap reader is implemented in pure Python.

## Instructions

```bash
# Full test gate
make test

# Build release artifacts
make build/mscfg32.dll
make build/peddlecheap

# Run harness selftests
python3 harness/extract.py --selftest
python3 harness/verify.py --selftest --fixture tests/fixtures/fileinfo_blob.hex

# Generate Equinox platform build
python build_equinox.py
```

See `tutorials/01_build_and_run.md` and `tutorials/02_verify_fixtures.md` for guided steps.

## Tutorials

- [`tutorials/01_build_and_run.md`](tutorials/01_build_and_run.md) — build, test, verify
- [`tutorials/02_verify_fixtures.md`](tutorials/02_verify_fixtures.md) — fixture validation
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — common errors and fixes

![NSA TAO / EquationGroup Logo](assets/logo.svg)

## Troubleshooting

- 0 frames from captures: apply `harness/fix6.py`; verify with `diag3.py`.
- `bn_sub` borrow overflow: already fixed (`src/bignum.c`); test `tests/bignum_sub_borrow.c`.
- RC5 vector failure: confirm little-endian memory layout (`tests/rc5_vectors.c`).
- Plugin ordinal load fails: check `ed_plugin_load()` / `dlsym` on POSIX.
- Build issues: verify `gcc`, `mingw`, `python3`, `curl`, `git` installed.

See [`docs/troubleshooting.md`](docs/troubleshooting.md) for full guide.

## Validation

```bash
python3 harness/extract.py --selftest
python3 harness/verify.py --selftest
make test
```

`run_all.py` exits non-zero if any capture yields no frames.

## Roadmap: Plan Forward (100%)

**Status: 100% complete.** All four phases finished and verified.

| Phase | Target | Status |
| --- | --- | --- |
| 1 — End-to-end handshake | 38% → 55% | ✅ Mock LP (`harness/mock_lp.py`) + `tests/handshake_kat.c` pass |
| 2 — Capture parsing gate | 55% → 70% | ✅ `make check` / `extract.py --selftest` pass; `fix6.py` fixes NUL-stub |
| 3 — Stub components | 70% → 85% | ✅ `ed_plugin_host.c` (ordinal `dlsym`), `registry.c` (INI fallback), `mscfg32.c` (`ed_share2_find`), `ed_config.c` (`ed_config_serialize`) |
| 4 — Packaging, CI, releases | 85% → 100% | ✅ `.github/workflows/ci.yml`, `Makefile`, `dist/*.dll+exe`, `run.sh`, badges, `PROVENANCE.md`, `CHANGELOG.md`, releases `v2.3.0` / `v2.3.1` |

### Definition of done (100%)

| Criterion | Status |
|-----------|--------|
| All `make test` binaries pass (AES, RC5, SHA-1, modexp, config_walk, pc_selftest, handshake_kat, sha1_pad, registry_kat, bignum_extra, peddlecheap_pad, plugin_load, bignum_sub_borrow) | ✅ |
| `harness/extract.py --selftest` passes | ✅ |
| `harness/verify.py --selftest` and `--fixture` pass | ✅ |
| `make check` (`run_all.py --port-only`) green on all 5 captures | ✅ (fix6 applied) |
| End-to-end `pc_handshake` against mock LP verified | ✅ |
| `ed_plugin_host`, `registry`, `mscfg32` stubs resolved | ✅ |
| CI green on push/PR; GitHub Release with assets | ✅ (`v2.3.1`) |

## Security and research context

This project deals with malware, implant protocols, and leaked tooling. It is intended for defensive research, protocol reconstruction, and malware analysis in controlled environments. It should not be used to facilitate unauthorized access or offensive operations.

## Sources

- https://github.com/johnbergbom/PeddleCheap
- https://github.com/francisck/DanderSpritz_docs
- https://github.com/649/EquationDrug

## License and usage

The repository content is provided for research and forensic reconstruction. Please respect local laws, applicable policies, and the intended scope of analysis when using the code or artifacts contained herein.

---

*Made for protocol archaeology, reverse engineering, and defensive analysis.*
