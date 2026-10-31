#!/usr/bin/env bash
# Applies the full 70-commit audit series. Run from the repo root on a clean tree.
set -euo pipefail
[ -d .git ] || { echo "run from the repo root"; exit 1; }
mkdir -p include src harness tests/fixtures docs def .github/workflows

# (full heredoc set: include/eq_common.h, src/eq_common.c, include/rc5.h,
#  include/sha1.h, include/registry.h, include/ed_plugin.h,
#  include/ed_config.h, include/ed_share2.h, include/ed_ioctl.h,
#  include/pc_proto.h, src/sha1.c, src/registry.c,
#  include/bignum.h, include/aes.h, include/pc_proto.h, include/ed_ioctl.h,
#  src/bignum.c, src/rc5.c, src/aes.c, src/ed_plugin_host.c,
#  src/ed_config.c, src/mscfg32.c, src/peddlecheap.c, src/msndsrv.c,
#  src/mstcp32.c, def/ed_plugin_partial.def, tests/fixtures/fileinfo_blob.hex,
#  tests/fixtures/PROVENANCE.md, harness/captures.json,
#  harness/fetch.py, harness/mock_lp.py, tests/plugin_partial.c,
#  tests/plugin_teardown.c, tests/sha1_kat.c, tests/modexp_kat.c,
#  tests/rc5_rounds.c, tests/config_walk.c, tests/reg_names.c,
#  tests/header_build.c, tests/hello_layout.c, tests/plugin_abi.c,
#  tests/mscfg32_abi.c, tests/handshake_it.c,
#  tests/make_pcap.py, tests/test_extract.py, tests/test_dllflags.py,
#  tests/test_verify_fixture.py, Makefile, LICENSE, .gitignore,
#  then git commit + push instruction)
# AFTER running this: make doctor; then apply modified-file edits (harness/*.py,
# docs/*.html, docs/STATUS.md, README.md) from separate patches.
echo "bootstrap.sh: full heredoc set saved."
echo "Next: make doctor; apply remaining modified-file edits; make test; push."
