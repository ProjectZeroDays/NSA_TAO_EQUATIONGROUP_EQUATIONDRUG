#include "pc_proto.h"
#include "eq_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FRAME 4096
#define EXE_LEN (3 * FRAME)
static void build_pubkey(u8 *pk)
{
    eq_put_be32(pk, 256);
    memset(pk + 4, 0xFF, 256);
    memset(pk + 4 + 256, 0, 256);
    pk[4 + 256 + 254] = 0x01;
    pk[4 + 256 + 255] = 0x01;
}
int main(int argc, char **argv)
{
    pc_session_t s;
    u8 pk[PC_PUBKEY_LEN];
    static u8 exe[EXE_LEN + 64];
    size_t n = 0;
    int fails = 0, i, rc;
    unsigned long port;
    FILE *f;
    if (argc < 3) { fprintf(stderr, "usage: handshake_it <port> <dir> [expect-fail]\n"); return 2; }
    port = strtoul(argv[1], NULL, 10);
    if (!port || port > 65535) { fprintf(stderr, "bad port\n"); return 2; }
    build_pubkey(pk);
    if (pc_session_init(&s, "127.0.0.1", (u16)port, "TlEo") != EQ_OK) return 2;
    s.timeout_ms = 5000;
    pc_handshake_begin(&s);
    if ((f = fopen("build/key.bin", "wb"))) { fwrite(s.session_key, 1, 16, f); fclose(f); }
    if ((f = fopen("build/iv.bin", "wb"))) { fwrite(s.iv, 1, 16, f); fclose(f); }
    if (argc > 3 && !strcmp(argv[3], "expect-fail")) {
        rc = pc_handshake(&s, pk, sizeof pk, exe, sizeof exe, &n);
        if (rc != EQ_ERR_CRYPTO) { printf("FAIL expected EQ_ERR_CRYPTO, got %d (%s)\n", rc, eq_strerror(rc)); return 1; }
        printf("handshake_it: PASS (no-magic rejected)\n");
        return 0;
    }
    for (i = 0; i < 12; i++) {
        rc = pc_handshake_step(&s, pk, sizeof pk, exe, sizeof exe, &n);
        if (rc != EQ_MORE) { printf("FAIL step %d rc=%d (%s)\n", i, rc, eq_strerror(rc)); return 1; }
    }
    rc = pc_handshake_step(&s, pk, sizeof pk, exe, sizeof exe, &n);
    if (rc != EQ_OK) { printf("FAIL final rc=%d (%s)\n", rc, eq_strerror(rc)); return 1; }
    if (n != EXE_LEN) { printf("FAIL exe len %zu\n", n); fails++; }
    for (i = 0; i < 3; i++)
        if (n >= (size_t)(i + 1) * FRAME && exe[(size_t)i * FRAME] != (u8)(0xA0 + i)) { printf("FAIL order %d\n", i); fails++; }
    if (s.crypto_on && s.sub_msg >= 2) { printf("PASSED handshake steps\n"); }
    if (!s.crypto_on) { printf("FAIL crypto off\n"); fails++; }
    if (s.sub_msg < 2) { printf("FAIL sub_msg %d\n", s.sub_msg); fails++; }
    printf("handshake_it: %s (%zu exe bytes)\n", fails ? "FAIL" : "PASS", n);
    return fails ? 1 : 0;
}
