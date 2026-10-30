#ifndef BIGNUM_H
#define BIGNUM_H
#include "eq_common.h"
#include <stdint.h>
#include <stddef.h>

#define BN_LIMBS 32
#define BN_WIDE_LIMBS (BN_LIMBS * 2)

typedef struct { u64 w[BN_LIMBS]; } bn;
void bn_from_bytes(bn *r, const u8 *be, size_t len);
void bn_to_bytes(u8 *be, size_t len, const bn *a);
int  bn_modexp(u8 *out, size_t outlen, const u8 *base, size_t blen,
               const u8 *exp, size_t elen, const u8 *mod, size_t mlen);
#endif