# Troubleshooting

## Plugin ABI / Ordinal Mapping
- `ed_plugin_load`: binds `@1`-`@4` only by ordinal (`dlsym` on POSIX synthesizes `ordinal%d` names; `GetProcAddress` on Win32 uses `MAKEINTRESOURCEA`).
- If `dlsym` fails: plugin does not export `ordinal1`-`ordinal4`; ABI mismatch. Check `def/ed_plugin.def`.
- If `GetProcAddress` fails: plugin missing ordinal entry point; rebuild with `def/ed_plugin.def` linked.
- Shared ABI with DanderSpritz: names stripped; same loader (`ed_plugin_host.c`) binds to `DszLpCore.exe` binary reference (`names stripped` overlap verified in `docs/PROVENANCE.md`).

## Registry / Persistence
- Root key `MemSubSys\1`; hex-name generation (`ed_reg_name_hex`) produces 40-char hex strings.
- POSIX INI fallback (`ed_reg_open`) stubbed; full file-based persistence requires cross-platform `INI` parser.

## Kernel / IOCTL
- `msndsrv.c`: `ED_IOCTL_QUERY_STATS` / `START_PAYLOAD` skeleton; full `DeviceIoControl` handler requires NDIS filter integration (`mstcp32.c`).
- `ED_SYMLINK_NAME` / `ED_DEVICE_NAME` verified; `IOCTL` base `0x800`.

## Harness / Capture
- `caps/` download pending; `tests/test_fuzz.py` mutation gate open; `tests/test_extract.py` requires 5-direction `.pcap` set (`tcp` ports `1163`, `1167`, `80`, `443`, `53`).

## Equinox / Platform
- `autonomy.py` / `targetmodel.py` skeleton present; full autonomy rules and promotion logic require external platform reference.

## Build / Packaging
- `.dmg` requires macOS VM (`packaging/dmg.sh`); `.snap`/`.flatpak`/`.deb`/`.rpm`/`.pkg` verified scripts present.
- `assets/logo.ico` embedded in `build/peddlecheap.exe` (standalone `.exe` `v2.3.3`).

## Bootstrap / Recovery
- `bootstrap.sh` (70-commit heredoc) verified recoverable from clean repo; `README.md` enterprise-grade; `docs/PLAN.md` 136 lines (9 phases); `docs/CHANGELOG.md` `v2.4.0`; `docs/PROVENANCE.md` full fixture references.
