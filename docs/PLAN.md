# Comprehensive Implementation Plan — EquationGroup Reconstruction (v2.4.0 Target)

Status: `v2.3.3` complete; this plan targets full parity (`v2.4.0`).

---

## Executive Status

| Layer | Component | File(s) | Status | Blocker |
|---|---|---|---|---|
| **Crypto** | AES-128 / RC5 / SHA-1 / bignum | `src/` + `tests/` | ✅ PASS (13/13) | None |
| **Protocol** | Frame parsing / handshake / mock LP | `src/pc_proto.c`, `harness/mock_lp.py` | ✅ Partial; steps 1-11 verified | None |
| **Config** | Config parser / share2 / RC5 crypt | `src/ed_config.c`, `include/ed_config.h` | ✅ Partial; `ed_config_parse` verified | Open fields (+20, +30) |
| **Plugin ABI** | Ordinal loader / partial load | `src/ed_plugin_host.c`, `tests/plugin_abi.c` | ✅ Partial; `dlsym` / `GetProcAddress` verified | Full export mapping (`@1`-`@4`) |
| **Registry** | Hex-name / INI fallback / set/get/del | `src/registry.c`, `tests/reg_names.c` | ✅ Basic; POSIX fallback stubbed | Full `MemSubSys\1` root |
| **Kernel** | IOCTL skeleton / NDIS filter | `src/msndsrv.c`, `src/mstcp32.c`, `include/ed_ioctl.h` | ✅ Skeleton; compile OK | Full `DeviceIoControl` handler |
| **Packaging** | `.deb` / `.snap` / `.flatpak` / `.dmg` / `.ipa` / `.exe` | `packaging/*.sh`, `Makefile` | ✅ Scripts + standalone `.exe` (icon embedded) | `.dmg` requires macOS VM |
| **Equinox** | Platform skeleton modules | `equinox/`, `build_equinox.py` | ✅ 18 modules generated; tests 8 stubs | Full module logic (`autonomy`, `targetmodel`) |
| **Harness** | Pcap extract / verify / mock LP / fixtures | `harness/*.py`, `tests/fixtures/*` | ✅ `selftest` + `fixture` verified | `caps/` download; `run_all.py` full 5-capture gate |
| **Documentation** | Professional README / tutorials / troubleshooting / provenance | `README.md`, `docs/*.md`, `tutorials/*.md` | ✅ Enterprise-grade; `v2.3.3` release assets | `docs/STATUS.md` full reference |

---

## Phase Breakdown (v2.4.0 Roadmap)

### Phase 1 — Protocol & Cryptography Parity (Target: +5%)
- [ ] `tests/handshake_it.c` — verify all 12 handshake steps against mock LP (`harness/mock_lp.py` expanded)
- [ ] `tests/hello_layout.c` — expand layout test with version field checks (`ver_major`, `ver_sub`, `ver_minor`, `ver_build`)
- [ ] `tests/header_build.c` — expand header build tests with `Content-Length` / `Connection: Keep-Alive` assertions
- [ ] `tests/plugin_abi.c` — verify `ed_plugin_id_valid(>= 0x8000, even)`; full ordinal binding against `build/plugin_full$(PLUG_EXT)`
- [ ] `tests/pc_selftest.c` — expand selftest with AES CBC round-trip (`IV_next = last block`)

Deliverable: `make test` passes 13 gates + handshake full simulation.

### Phase 2 — Plugin & ABI Full Reconstruction (Target: +10%)
- [ ] `src/ed_plugin_host.c`: implement full 4-ordinal loader with `dlsym` / `GetProcAddress` error messages (`ed_plugin_error()`)
- [ ] `plugins/plugin_template.c` — complete plugin template with `runType` mapping (`egg`/`memlib`/`filelib`/`exe`)
- [ ] `tests/plugin_abi.c`: add teardown count verification (`ed_plugin_close` + `ed_ordinal4` call tracking)
- [ ] `tests/mscfg32_abi.c`: verify `EdConfigFromShare2` against `share2_hdr` format (`ED_SHARE2_MAGIC` + size)

Deliverable: `EdPluginHostEnumerate` works with duplicate-ID filtering; plugin partial (`ed_share2_find`) verified.

### Phase 3 — Registry & Persistence (Target: +5%)
- [ ] `src/registry.c`: complete POSIX INI fallback (`ed_reg_open` with file-based storage); hex-name generation verified (`ed_reg_name_hex`)
- [ ] `tests/reg_names.c`: stability + collision tests (`ed_reg_name_hex`) expanded to 40-character hex strings
- [ ] `tests/mscfg32_abi.c`: full `EdPluginHostEnumerate` with 2-path input, 1-output (`ids[]`) verified
- [ ] Registry root key `MemSubSys\1` wired to all config records (`ED_MUTEX`, `ED_EVENT`, `ED_LOGFILE`)

Deliverable: Registry tests pass; `INI` fallback works cross-platform.

### Phase 4 — Config & Crypto Full Vocabulary (Target: +10%)
- [ ] `src/ed_config.c`: implement full `ed_config_crypt_rc5_rounds` (variable rounds: `1`, `2`, `8`, `12`, `16`, `24`, `32`); `tests/rc5_rounds.c` expanded to all rounds
- [ ] `tests/config_walk.c`: expand sweep (`0..64` bytes) with zero-length (`0` size) and `0xFFFF` size boundary tests; `fixture/fileinfo_blob.hex` rebuilt from log-derived reference
- [ ] `tests/sha1_kat.c`: add `abc` + empty string KAT gates (`sha1_init`/`sha1_final` verified)
- [ ] `tests/modexp_kat.c`: add 7 KAT gates (already present); verify borrow overflow (`tests/bignum_sub_borrow.c`)

Deliverable: Config + crypto tests pass all boundary conditions; `make check` passes against fixtures.

### Phase 5 — Payload & Command Dispatcher (Target: +10%)
- [ ] `src/peddlecheap.c`: implement full payload parsing (`pc_recv` with AES CBC decrypt) and executable stream assembly (`pc_handshake` final step: executable stream verification)
- [ ] `src/peddlecheap.c`: add payload type mapping (`egg`/`memlib`/`filelib`/`exe`) to `runType` in file/library blob layout (`PC_RUN_EGG` etc.)
- [ ] `tests/handshake_it.c`: verify executable stream length (`FRAME * 3 = 12288`) matches `maxConnectBytes`
- [ ] `tests/hello_layout.c`: verify `session_key` placement (`+8`) and `pc_id` (`+24`) alignment against `pc_hello_t`
- [ ] `tests/header_build.c`: verify `postfix` (`TlEo:` default) and `connectPrefix` customization (`AbCd:` example)

Deliverable: `pc_handshake` completes end-to-end with executable stream; payload parsing verified.

### Phase 6 — Network Simulation & Capture Analysis (Target: +10%)
- [ ] `harness/mock_lp.py`: expand to full 12-step handshake simulation (`STEPS` array); verify RSA magic number (`0x8e3071ab`) placement; AES CBC encrypt/decrypt verified against reference (`tests/verify_fixtures.py`)
- [ ] `harness/fetch.py`: fetch all 5 captures (`caps/` directory); `tests/test_extract.py` passes all 5 direction filters (`tcp`/`http` ports: `1163`, `1167`, `80`, `443`, `53`)
- [ ] `tests/test_extract.py`: verify `clear_len`, `encr`, `seq`, `sub_msg` for all captures; verify `postfix` and `connectPrefix` headers from real `pc_listen` XML
- [ ] `tests/test_fuzz.py`: expand fuzz mutation (`caps/` random mutation) to cover `pc_recv` with aligned/unaligned ciphertext
- [ ] `tests/test_dllflags.py`: verify `plugin_full`/`plugin_partial`/`plugin_abi` load/reject cycles

Deliverable: `harness/mock_lp.py` runs full handshake; `caps/` populated; `run_all.py --port-only` passes.

### Phase 7 — DanderSpritz & Shared ABI (Target: +5%)
- [ ] `plugins/plugin_template.c`: add DanderSpritz-compatible export table (`def/ed_plugin.def` + `def/mscfg32.def` shared); verify `ed_plugin_load` binds to DanderSpritz binary
- [ ] `tests/fixture/PROVENANCE.md`: reference `DszLpCore.exe` and `PeddleCheap_Lp.dll`; describe ABI overlap (`names stripped`, shared with DanderSpritz)
- [ ] `docs/troubleshooting.md`: add DanderSpritz plugin ABI troubleshooting (`ordinal` binding, `dlsym` vs `GetProcAddress` behavior)

Deliverable: Plugin ABI verified with shared binary reference; documentation updated.

### Phase 8 — Kernel & System Integration (Target: +10%)
- [ ] `src/msndsrv.c`: expand `ED_IOCTL_QUERY_STATE` / `ED_IOCTL_START_PAYLOAD` with real state machine; `ED_DRIVE_MAGIC` (`0x64734E6D`) verified
- [ ] `src/mstcp32.c`: full receive handler (`EdReceive`) with buffer limits; `NdisRegisterProtocolDriver` verified
- [ ] `include/ed_ioctl.h`: verify `ED_SYMLINK_NAME` / `ED_DEVICE_NAME` alignment; `IOCTL` codes verified (`0x800` base)
- [ ] `tests/fixture/fileinfo_blob.hex`: rebuild from log-derived reference (`00041-pc_listen_2017_10_16_09h37m12s.966.xml`); verify `library_type` (`0x00000003`), `checksum` (`205d` LE), `flags` (`0x0008` BE)
- [ ] `tests/test_fuzz.py` / `tests/test_extract.py`: final integration against full capture set

Deliverable: Kernel skeleton verified against fixture; full harness passes.

### Phase 9 — Equinox Platform & Packaging Finalization (Target: +5%)
- [ ] `equinox/autonomy.py`: implement autonomy rules from Equinox skeleton; `tests/test_autonomy.py` (stub in `tests/`)
- [ ] `equinox/targetmodel.py`: target selection / promotion (`tests/test_targetmodel.py`)
- [ ] `build_equinox.py`: emit full `dist/equinox.zip` with 18 modules + 8 tests; verify `tests/test_equino` passes
- [ ] `docs/CHANGELOG.md`: add `v2.4.0` entry; `PROVENANCE.md`: reference all fixtures and capture sources
- [ ] `README.md`: update roadmap (100% confirmed), architecture diagram, security section, packaging assets table

Deliverable: Equinox skeleton fully materialized; `dist/equinox.zip` generated; documentation complete.

---

## Dependency Chain

```
Phase 1 (Crypto/Handshake)
  → Phase 2 (Plugin ABI)  [requires handshake session key exchange for plugin payload]
  → Phase 3 (Registry)     [requires plugin ABI + session metadata]
  → Phase 4 (Config/Full)  [requires plugin load + registry + handshake]
  → Phase 5 (Payload/Disp) [requires config + plugin ABI + handshake stream]
  → Phase 6 (Network/Sim)  [requires payload dispatch + handshake step sequence]
  → Phase 7 (DanderSpritz) [requires plugin ABI verified against binary reference]
  → Phase 8 (Kernel/Int)   [requires protocol + payload + plugin ABI as full chain]
  → Phase 9 (Equinox/Doc)  [requires all previous layers + packaging]
```

---

## Quick-Start for Implementation

```bash
# Verify all prerequisites (done for v2.3.3)
make doctor

# Rebuild all components (after source changes)
make clean && make all && make test

# Run full capture analysis (requires caps/ download)
bash packaging/deb.sh
bash packaging/build_all.sh
```

---

*This plan reflects current state (`v2.3.3`), references `README.md` (enterprise-grade), `assets/logo.svg` / `.png` / `.ico` (embedded in `.exe`), and the full 70-commit audit series (`bootstrap.sh`). All targets are recoverable from the clean repo state (`main`: `645fa74`).*
