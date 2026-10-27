CC      ?= x86_64-w64-mingw32-gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -Iinclude
LDFLAGS ?= -lws2_32

CORE := src/eq_common.c src/rc5.c src/aes.c src/bignum.c
DLL  := $(CORE) src/mscfg32.c src/ed_config.c src/ed_plugin_host.c src/registry.c
EXE  := $(CORE) src/peddlecheap.c

all: build/mscfg32.dll build/peddlecheap.exe
build:
	@mkdir -p build
build/mscfg32.dll: $(DLL) def/mscfg32.def | build
	$(CC) $(CFLAGS) -shared -o $@ $(DLL) def/mscfg32.def $(LDFLAGS)
build/peddlecheap.exe: $(EXE) | build
	$(CC) $(CFLAGS) -o $@ $(EXE) $(LDFLAGS)
build/rc5_vectors.exe: tests/rc5_vectors.c src/rc5.c src/eq_common.c | build
	$(CC) $(CFLAGS) -o $@ $^
build/aes_vectors.exe: tests/aes_vectors.c src/aes.c src/eq_common.c | build
	$(CC) $(CFLAGS) -o $@ $^
build/pc_selftest.exe: tests/pc_selftest.c src/rc5.c src/aes.c src/eq_common.c | build
	$(CC) $(CFLAGS) -o $@ $^
test: build/rc5_vectors.exe build/aes_vectors.exe build/pc_selftest.exe
	./build/rc5_vectors.exe && ./build/aes_vectors.exe && ./build/pc_selftest.exe
clean:
	rm -rf build
.PHONY: all test clean
