CC      ?= gcc
MINGW   ?= x86_64-w64-mingw32-gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -Iinclude
WARN    := -Werror=implicit-function-declaration

CORE := src/eq_common.c src/rc5.c src/aes.c src/bignum.c src/sha1.c
DLL  := $(CORE) src/mscfg32.c src/ed_config.c src/ed_plugin_host.c src/registry.c
EXE  := $(CORE) src/peddlecheap.c
TESTS := build/rc5_vectors build/aes_vectors build/sha1_kat build/modexp_kat build/pc_selftest build/config_walk

all: build/peddlecheap build/mscfg32.dll
build:
	@mkdir -p build
build/peddlecheap: $(EXE) | build
	$(CC) $(CFLAGS) $(WARN) -o $@ $(EXE)
build/mscfg32.dll: $(DLL) def/mscfg32.def | build
	$(MINGW) $(CFLAGS) $(WARN) -shared -o $@ $(DLL) def/mscfg32.def -lws2_32
build/rc5_vectors: tests/rc5_vectors.c src/rc5.c src/eq_common.c | build
	$(CC) $(CFLAGS) -o $@ $^
build/aes_vectors: tests/aes_vectors.c src/aes.c src/eq_common.c | build
	$(CC) $(CFLAGS) -o $@ $^
build/sha1_kat: tests/sha1_kat.c src/sha1.c | build
	$(CC) $(CFLAGS) -o $@ $^
build/modexp_kat: tests/modexp_kat.c src/bignum.c src/eq_common.c | build
	$(CC) $(CFLAGS) -o $@ $^
build/pc_selftest: tests/pc_selftest.c src/eq_common.c | build
	$(CC) $(CFLAGS) -o $@ $^
build/config_walk: tests/config_walk.c src/ed_config.c src/rc5.c src/eq_common.c | build
	$(CC) $(CFLAGS) -o $@ $^

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done
	python3 harness/extract.py --selftest
	python3 harness/verify.py --selftest
	python3 harness/verify.py --fixture tests/fixtures/fileinfo_blob.hex

check: test
	python3 harness/run_all.py caps --port-only

clean:
	rm -rf build
.PHONY: all test check clean