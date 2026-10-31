/* KATs built on n = 2^2048 - 1, where reduction is exactly checkable by hand:
   2^65537 = 2*(2^2048)^32 = 2 mod n, and (2^2047)^2 = 2^4094 = 2^2046 mod n. */
#include "bignum.h"
#include <stdio.h>
#include <string.h>

#define N 256
static u8 mod[N], base[N], exp_[N], out[N];

static void be_bit(u8 *b, int bit) { memset(b, 0, N); b[N - 1 - (bit / 8)] |= (u8)(1u << (bit % 8)); }
/* big-endian u32 at the END of the buffer (for full-width N-byte reads) */
static void be_u32(u8 *b, u32 v) { memset(b, 0, N); b[N-4]=(u8)(v>>24); b[N-3]=(u8)(v>>16); b[N-2]=(u8)(v>>8); b[N-1]=(u8)v; }
/* put a small value at byte 0 (for blen=1 reads) */
static void put_byte0(u8 *b, u8 v) { memset(b, 0, N); b[0] = v; }
static int is_pow2(const u8 *b, int bit) {
    int i; for (i = 0; i < N; i++) if (b[i] != 0) {
        if (i != N - 1 - (bit / 8)) return 0;
        if (b[i] != (u8)(1u << (bit % 8))) return 0; }
    return b[N - 1 - (bit / 8)] == (u8)(1u << (bit % 8));
}

int main(void)
{
    int fails = 0;
    memset(mod, 0xFF, N);                       /* 2^2048 - 1 */

    /* Case 1: 2^65537 mod (2^2048-1) == 2  (full-width read) */
    be_u32(base, 2); be_u32(exp_, 65537);
    if (bn_modexp(out, N, base, N, exp_, N, mod, N) != EQ_OK || out[N - 1] != 2) {
        printf("FAIL case 1 (2^65537 mod 2^2048-1): out[N-1]=%d\n", out[N-1]); fails++; }

    /* Case 2: (2^2047)^2 mod (2^2048-1) == 2^2046  (full-width operands) */
    be_bit(base, 2047); put_byte0(exp_, 2);   /* exp=2 at byte 0 for elen=1 */
    if (bn_modexp(out, N, base, N, exp_, 1, mod, N) != EQ_OK || !is_pow2(out, 2046)) {
        printf("FAIL case 2 (full-width product)\n"); fails++; }

    /* Case 3: 7^5 mod 13 == 11  (small operands, blen=1 reads byte 0) */
    put_byte0(base, 7); put_byte0(exp_, 5); put_byte0(mod, 13);
    if (bn_modexp(out, N, base, 1, exp_, 1, mod, 1) != EQ_OK || out[N - 1] != 11) {
        printf("FAIL case 3 (7^5 mod 13): out[N-1]=%d\n", out[N-1]); fails++; }

    /* Case 4: mod 1 -> 0  (small operands) */
    put_byte0(mod, 1); put_byte0(base, 9); put_byte0(exp_, 4);
    if (bn_modexp(out, N, base, 1, exp_, 1, mod, 1) != EQ_OK || out[N - 1] != 0) {
        printf("FAIL case 4 (m == 1): out[N-1]=%d\n", out[N-1]); fails++; }

    /* Case 5: e == 0 -> 1  (full-width base/mod, exp=0 at byte 0) */
    memset(mod, 0xFF, N); put_byte0(exp_, 0);
    if (bn_modexp(out, N, base, N, exp_, 1, mod, N) != EQ_OK || out[N - 1] != 1) {
        printf("FAIL case 5 (e == 0): out[N-1]=%d\n", out[N-1]); fails++; }

    /* Case 6: base > modulus, pre-reduction path (Commit 7) */
    put_byte0(base, 5); put_byte0(exp_, 3);
    {
        u8 mod2[N]; memset(mod2, 0, N); mod2[0] = 3; mod2[1] = 232;  /* 1000 = 0x03E8 */
        /* 5^3 = 125 < 1000, so result is 125 */
        if (bn_modexp(out, N, base, 1, exp_, 1, mod2, 2) != EQ_OK || out[N - 1] != 125) {
            printf("FAIL case 6 (base > modulus): out[N-1]=%d\n", out[N-1]); fails++; }
    }

    /* Case 7: self-aliasing acc path: 2^2048 mod n == 1 */
    be_u32(base, 2);                          /* base = 2 (full width) */
    {
        u8 exp2[N]; memset(exp2, 0, N); exp2[0] = 8;  /* 2048 = 0x0800, elen=2 reads bytes 0-1 */
        if (bn_modexp(out, N, base, N, exp2, 2, mod, N) != EQ_OK || out[N - 1] != 1) {
            printf("FAIL case 7 (acc aliasing): out[N-1]=%d\n", out[N-1]); fails++; }
    }

    printf("modexp_kat: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}