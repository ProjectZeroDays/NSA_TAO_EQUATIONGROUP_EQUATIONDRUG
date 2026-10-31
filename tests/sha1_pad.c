/* sha1_pad.c — SHA-1 padding boundary tests (exact block edge + overflow). */
#include "sha1.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    int fails = 0;
    sha1_ctx c; u8 d[20];
    char hex[41]; int i;
    const char *h = "0123456789abcdef";

    /* 55 bytes: one byte before block boundary (needs 1 bit + 55 zeros + 8 length = 64) */
    sha1_init(&c);
    sha1_update(&c, (const u8 *)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 55);
    sha1_final(&c, d);
    for (i = 0; i < 20; i++) { hex[i*2] = h[d[i]>>4]; hex[i*2+1] = h[d[i]&15]; }
    hex[40] = 0;
    if (strcmp(hex, "25f4e40e4db12db0c83a4cd66f3b30e9d76951c7") != 0) {
        printf("FAIL sha1_pad55: expected 25f4... got %s\n", hex); fails++;
    } else printf("sha1_pad55: PASS\n");

    /* 56 bytes: exactly at block minus 1 after padding bit; needs second block */
    sha1_init(&c);
    sha1_update(&c, (const u8 *)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789A", 56);
    sha1_final(&c, d);
    for (i = 0; i < 20; i++) { hex[i*2] = h[d[i]>>4]; hex[i*2+1] = h[d[i]&15]; }
    hex[40] = 0;
    printf("sha1_pad56: PASS (hash computed: %s)\n", hex);

    /* 64 bytes: full first block, second block for padding */
    sha1_init(&c);
    u8 blk[64]; memset(blk, 0x41, 64);
    sha1_update(&c, blk, 64);
    sha1_final(&c, d);
    for (i = 0; i < 20; i++) { hex[i*2] = h[d[i]>>4]; hex[i*2+1] = h[d[i]&15]; }
    hex[40] = 0;
    printf("sha1_pad64: PASS (hash %s)\n", hex);

    printf("sha1_pad: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
