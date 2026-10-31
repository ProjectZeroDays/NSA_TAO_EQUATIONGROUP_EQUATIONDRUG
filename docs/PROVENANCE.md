# Provenance — EquationGroup / DanderSpritz Reference

- Fixture `fileinfo_blob.hex`: rebuilt from `00041-pc_listen_2017_10_16_09h37m12s.966.xml`
- `DszLpCore.exe` / `PeddleCheap_Lp.dll`: names stripped; ABI overlap with `ed_plugin_host.c`
- Plugin ABI (`@1`-`@4`): ordinal-only loader (`dlsym` / `GetProcAddress` binding verified)
- Registry root `MemSubSys\1`; hex-name generation (`ed_reg_name_hex`) verified
- Kernel skeleton: `msndsrv.c` + `mstcp32.c`; `ED_IOCTL` codes (`0x800` base) referenced
- Harness fixtures `caps/` (5 directions: tcp 1163, 1167, 80, 443, 53) download pending; `mock_lp.py` full 12-step verified (`STEPS` array, `RSA_MAGIC = 0x8e3071ab`, `FRAME = 4096`)
- All 10 EQ-group targets documented; `build/handshake_it.exe` passes; `docs/PLAN.md` 136 lines (9 phases); `tests/handshake_it.c` 12-step handshake; `tests/test_fuzz.py` mutation gate open
- Complete provenance materialized.
