#include "bignum.h"
#include <stdio.h>
#include <string.h>

int main() {
    u8 base[256], exp[256], mod[256], out[256];
    /* 7^3 mod 13 = 343 mod 13 = 5 */
    /* 7^3 = 343 = 0x151 in hex (256-bit) */
    memset(base, 0, 256); 
    base[255-2] = 0x15;  /* 343 = 0x151 */
    memset(exp, 0, 256);
    exp[255] = 3;  /* exponent = 3 */
    memset(mod, 0, 256);
    mod[255] = 13;  /* modulus = 13 */
    
    int rc = bn_modexp(out, 256, base, 3, exp, 1, mod, 1);
    printf("7^3 mod 13 = %d (expected 5), rc=%d\n", out[255], rc);
    
    return 0;
}