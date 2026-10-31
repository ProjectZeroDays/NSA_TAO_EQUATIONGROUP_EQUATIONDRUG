/* KATs built on n = 2^2048 - 1, where reduction is exactly checkable by hand:
   2^65537 = 2*(2^2048)^32 = 2 mod n, and (2^2047)^2 = 2^4094 = 2^2046 mod n. */
#include "bignum.h"
#include <stdio.h>
#include <string.h>

#define N 256
static u8 mod[N], base[N], exp_[N], out[N];

static void be_bit(u8 *b, int bit) { memset(b, 0, N); b[N - 1 - (bit / 8)] |= (u8)(1u << (bit % 8)); }
static void be_u32(u8 *b, u32 v) { memset(b, 0, N); b[0]=(u8)(v>>24); b[1]=(u8)(v>>16); b[2]=(u8)(v>>8); b[3]=(u8)v; }
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

    /* Debug: print the bits for case 1 */
    printf("DEBUG: base bits for case 1:\n");
    for (int i = 0; i < N; i++) {
        if (base[i] != 0) printf("  base[%d] = %d (0x%02x)\n", i, base[i], base[i]);
    }

    be_u32(base, 2); be_u32(exp_, 65537);       /* 2^65537 mod n == 2 */
    if (bn_modexp(out, N, base, N, exp_, 3, mod, N) != EQ_OK || !is_pow2(out, 1)) {
        printf("FAIL case 1 (2^65537 mod 2^2048-1)\n"); fails++; }

    printf("modexp_kat: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}