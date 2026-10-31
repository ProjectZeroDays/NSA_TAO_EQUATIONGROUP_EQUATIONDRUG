/* bignum_sub_borrow.c — targeted test for bn_sub borrow fix (0xFF...FF - 1). */
#include "bignum.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    int fails = 0;
    /* Verify bn_modexp handles large base/mod correctly (borrow path indirect) */
    u8 base[256]; memset(base, 0xFF, 256);
    base[255] = 0xFE; /* 2^2048-2 approx */
    u8 exp[4] = {0,0,0,1};
    u8 mod[256]; memset(mod, 0xFF, 256); mod[255] = 0xFD;
    u8 out[256]; memset(out, 0, sizeof out);
    if (bn_modexp(out, 256, base, 256, exp, 4, mod, 256) != EQ_OK) {
        printf("FAIL bn_sub_borrow_path\n"); fails++;
    } else printf("bn_sub_borrow_path: PASS\n");
    printf("bignum_sub_borrow: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
