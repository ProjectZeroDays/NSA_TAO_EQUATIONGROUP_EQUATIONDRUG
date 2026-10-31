#include "ed_config.h"
#include "rc5.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    int fails = 0;
    ed_record r[8];
    u8 blob[] = { 0x00,0x01, 0x00,0x02, 0xAA,0xBB,        /* type 1, 2 bytes */
                  0x00,0x02, 0x00,0x03, 0x01,0x02,0x03 }; /* type 2, 3 bytes */
    int n = ed_config_parse(blob, sizeof blob, r, 8);
    if (n != 2) { printf("FAIL parse count %d\n", n); fails++; }
    if (n == 2 && (r[0].type != 1 || r[0].size != 2 || r[1].type != 2 || r[1].size != 3)) {
        printf("FAIL record fields\n"); fails++; }
    if (n == 2 && ed_config_find(r, (size_t)n, 2) != &r[1]) { printf("FAIL find\n"); fails++; }
    if (ed_config_find(r, 2, 9) != NULL) { printf("FAIL find-miss\n"); fails++; }

    u8 trunc[] = { 0x00,0x01, 0x00,0x08, 0x01,0x02 };      /* declares 8, has 2 */
    if (ed_config_parse(trunc, sizeof trunc, r, 8) != EQ_ERR_ARG) {
        printf("FAIL truncation not rejected\n"); fails++; }

    u8 partial[] = { 0x00,0x01, 0x00,0x00, 0x00 };          /* trailing lone byte */
    if (ed_config_parse(partial, sizeof partial, r, 8) != EQ_ERR_ARG) {
        printf("FAIL trailing byte not rejected\n"); fails++; }

    if (ed_config_parse(blob, sizeof blob, r, 1) != EQ_ERR_ARG) {
        printf("FAIL max clamp not reported\n"); fails++; }

    static const u8 key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    static const u8 iv[8]  = {9,8,7,6,5,4,3,2};
    u8 rt[16] = "0123456789abcdef", orig[16];
    memcpy(orig, rt, 16);
    if (ed_config_crypt_rc5(rt, 16, key, 16, iv, 1) != EQ_OK ||
        ed_config_crypt_rc5(rt, 16, key, 16, iv, 0) != EQ_OK ||
        memcmp(rt, orig, 16)) { printf("FAIL rc5 round-trip\n"); fails++; }

    u8 odd[13] = {0};
    if (ed_config_crypt_rc5(odd, 13, key, 16, iv, 0) != EQ_ERR_ARG) {
        printf("FAIL unaligned length not rejected\n"); fails++; }

    printf("config_walk: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}