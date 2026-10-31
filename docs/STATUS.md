# STATUS — 13 Pass Gates

1. Crypto (AES-128 / RC5 / SHA-1 / bignum) — PASS
2. Protocol handshake (tests/handshake_it.c, 12 steps) — PASS
3. Plugin ABI (ed_plugin_host.c, ordinal @1-4) — PASS
4. Registry (registry.c, hex-name, POSIX fallback stub) — PASS
5. Config (ed_config.c, RC5 rounds, open fields +20/+30) — PASS
6. Payload dispatcher (peddlecheap.c stripped + pc_proto.c split) — PASS
7. Harness / mock_lp (harness/mock_lp.py 12-step, caps/ framework) — PASS
8. Kernel skeleton (msndsrv.c / mstcp32.c) — PARTIAL (full IOCTL handler missing)
9. Packaging (.deb/.snap/.flatpak/.exe; .dmg pending) — PASS
10. Equinox skeleton (build_equinox.py modules) — PARTIAL (autonomy/targetmodel logic pending)
11. Fixture rebuild (tests/fixture/fileinfo_blob.hex) — PASS
12. Fuzz mutation (tests/test_fuzz.py) — PASS
13. Provenance / docs (docs/PLAN.md, docs/PROVENANCE.md, docs/CHANGELOG.md) — PASS
