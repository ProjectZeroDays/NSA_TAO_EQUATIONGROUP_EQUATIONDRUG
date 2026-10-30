#include "bignum.h"
#include <string.h>

static void bn_zero(bn *r){ memset(r, 0, sizeof(*r)); }
static int bn_is_zero(const bn *a){ int i; for(i=0;i<BN_LIMBS;i++) if(a->w[i]) return 0; return 1; }
static int bn_cmp(const bn *a, const bn *b){
    int i; for(i=BN_LIMBS-1;i>=0;i--) if(a->w[i]!=b->w[i]) return a->w[i]>b->w[i]?1:-1; return 0; }
static void bn_sub(bn *r, const bn *a, const bn *b){
    int i; u64 borrow=0;
    for(i=0;i<BN_LIMBS;i++){ u64 x=a->w[i], y=b->w[i], d=x-y-borrow;
        borrow = (x < y + borrow) ? 1 : 0; r->w[i]=d; } }
static void bn_shl1(bn *r){ int i; u64 c=0; for(i=0;i<BN_LIMBS;i++){ u64 v=r->w[i]; r->w[i]=(v<<1)|c; c=v>>63; } }
static int bn_bit(const bn *a, int n){ return (a->w[n>>6]>>(n&63)) & 1; }
static int bn_bits(const bn *a){
    int i; for(i=BN_LIMBS-1;i>=0;i--) if(a->w[i]){ u64 v=a->w[i]; int b=0; while(v){b++;v>>=1;} return i*64+b; } return 0; }

void bn_from_bytes(bn *r, const u8 *be, size_t len)
{
    size_t i; bn_zero(r);
    if (len > (size_t)BN_LIMBS * 8) { be += len - (size_t)BN_LIMBS * 8; len = (size_t)BN_LIMBS * 8; }
    for (i = 0; i < len; i++) {
        size_t bit = (len - 1 - i) * 8;
        r->w[bit >> 6] |= (u64)be[i] << (bit & 63);
    }
}

void bn_to_bytes(u8 *be, size_t len, const bn *a)
{
    size_t i;
    for (i = 0; i < len; i++) {
        size_t bit = (len - 1 - i) * 8;
        be[i] = (bit >> 6) < BN_LIMBS ? (u8)(a->w[bit >> 6] >> (bit & 63)) : 0;
    }
}

static void bn_mulwide(u64 *prod, const bn *a, const bn *b)
{
    int i, j;
    memset(prod, 0, sizeof(u64) * BN_WIDE_LIMBS);
    for (i = 0; i < BN_LIMBS; i++) {
        u64 carry = 0;
        if (!b->w[i]) continue;
        for (j = 0; j < BN_LIMBS; j++) {
            unsigned __int128 p = (unsigned __int128)a->w[j] * b->w[i] + carry + prod[j + i];
            prod[j + i] = (u64)p;
            carry = (u64)(p >> 64);
        }
        prod[j + i] += carry;
    }
}

static void bn_reduce(bn *r, const u64 *wide, const bn *m)
{
    bn rem; int k, top = 0;
    bn_zero(&rem);
    for (k = BN_WIDE_LIMBS * 64 - 1; k >= 0; k--) {
        int carry = (int)((rem.w[BN_LIMBS - 1] >> 63) & 1);
        bn_shl1(&rem);
        rem.w[0] |= (wide[k >> 6] >> (k & 63)) & 1;
        if (top || bn_cmp(&rem, m) >= 0) bn_sub(&rem, &rem, m);
        top = carry;
    }
    memcpy(r, &rem, sizeof(bn));
}

static void bn_mulmod(bn *r, const bn *a, const bn *b, const bn *m)
{
    u64 prod[BN_WIDE_LIMBS];
    bn res;
    bn_mulwide(prod, a, b);
    bn_reduce(&res, prod, m);
    memcpy(r, &res, sizeof(bn));   /* safe when r aliases a or b */
}

/* reduce an n-limb value through a zero-extended wide buffer */
static void bn_mod(bn *r, const bn *a, const bn *m)
{
    u64 prod[BN_WIDE_LIMBS];
    bn res;
    memset(prod, 0, sizeof prod);
    memcpy(prod, a->w, sizeof(a->w));
    bn_reduce(&res, prod, m);
    memcpy(r, &res, sizeof(bn));
}

int bn_modexp(u8 *out, size_t outlen, const u8 *base, size_t blen,
              const u8 *exp, size_t elen, const u8 *mod, size_t mlen)
{
    if (blen > (size_t)BN_LIMBS * 8 || elen > (size_t)BN_LIMBS * 8 ||
        mlen > (size_t)BN_LIMBS * 8) return EQ_ERR_ARG;
    bn b, e, m, acc; int i, bits;
    bn_from_bytes(&b, base, blen);
    bn_from_bytes(&e, exp, elen);
    bn_from_bytes(&m, mod, mlen);
    if (bn_is_zero(&m)) return EQ_ERR_ARG;
    if (bn_cmp(&b, &m) >= 0) bn_mod(&b, &b, &m);  /* <--- FIXED */
    bn_zero(&acc); acc.w[0] = 1;
    bits = bn_bits(&e);
    while (bits > 0 && !((e.w[(bits - 1) >> 6] >> ((bits - 1) & 63)) & 1)) bits--;
    for (i = bits - 1; i >= 0; i--) {
        bn_mulmod(&acc, &acc, &acc, &m);
        if ((e.w[i >> 6] >> (i & 63)) & 1) bn_mulmod(&acc, &acc, &b, &m);
    }

    memset(out, 0, outlen);
    bn_to_bytes(out, outlen, &acc);
    return EQ_OK;
}