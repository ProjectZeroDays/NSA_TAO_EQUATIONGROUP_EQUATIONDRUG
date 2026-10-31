#include "sha1.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    int fails = 0;
    sha1_ctx c;
    u8 d[20];
    char hex[41];
    const char *hex_chars = "0123456789abcdef";
    int i;

    /* FIPS 180-1 example: SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d */
    sha1_init(&c);
    sha1_update(&c, (const u8 *)"abc", 3);
    sha1_final(&c, d);
    for (i = 0; i < 20; i++) { hex[i * 2] = hex_chars[d[i] >> 4]; hex[i * 2 + 1] = hex_chars[d[i] & 15]; }
    hex[40] = '\0';
    if (strcmp(hex, "a9993e364706816aba3e25717850c26c9cd0d89d") != 0) {
        printf("FAIL sha1 abc: got %s\n", hex); fails++;
    }

    /* Empty string: SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709 */
    sha1_init(&c);
    sha1_update(&c, (const u8 *)"", 0);
    sha1_final(&c, d);
    for (i = 0; i < 20; i++) { hex[i * 2] = hex_chars[d[i] >> 4]; hex[i * 2 + 1] = hex_chars[d[i] & 15]; }
    hex[40] = '\0';
    if (strcmp(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709") != 0) {
        printf("FAIL sha1 empty: got %s\n", hex); fails++;
    }

    printf("sha1_kat: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}