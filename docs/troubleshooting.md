# Troubleshooting

- 0 frames from `run_all.py`: apply `fix6.py` to `harness/pcapread.py`. Verify with `python harness/diag3.py` if needed.
- `bn_sub` borrow overflow: fixed in `bn_sub`; use `tests/bignum_sub_borrow.c`.
- RC5 vectors fail: confirm little-endian memory layout (`tests/rc5_vectors.c`).
- Plugin load fails: check `ed_plugin_load()` ordinal binding on POSIX (`dlsym`).
- Build errors: ensure `gcc`, `mingw`, `python3`, `curl`, `git` installed.
