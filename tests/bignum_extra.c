/* bignum_extra.c — public API edge cases. */
#include "bignum.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    int fails = 0;
    u8 out[32];

    /* modexp: base 0, exp 5, mod 7 => 0 */
    u8 base[] = {0,0,0,0};
    u8 exp[] = {0,0,0,5};
    u8 mod[] = {0,0,0,7};
    memset(out, 0, sizeof out);
    if (bn_modexp(out, 4, base, 4, exp, 4, mod, 4) != EQ_OK) { printf("FAIL modexp_base0\n"); fails++; }
    else if (out[3] != 0) { printf("FAIL modexp_base0_result\n"); fails++; }
    else printf("modexp_base0: PASS\n");

    /* modexp: exp 0 => 1 regardless of base */
    memset(out, 0, sizeof out);
    u8 b[] = {0,0,0,3};
    u8 e[] = {0,0,0,0};
    u8 m[] = {0,0,0,7};
    if (bn_modexp(out, 4, b, 4, e, 4, m, 4) != EQ_OK) { printf("FAIL modexp_exp0\n"); fails++; }
    else if (out[3] != 1) { printf("FAIL modexp_exp0_result (%d)\n", out[3]); fails++; }
    else printf("modexp_exp0: PASS\n");

    printf("bignum_extra: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
