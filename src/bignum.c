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
    int i; bn_zero(r);
    for (i = 0; i < (int)len; i++) {
        int bit = ((int)len - 1 - i) * 8;
        r->w[bit>>6] |= (u64)be[i] << (bit & 63);
    }
}
void bn_to_bytes(u8 *be, size_t len, const bn *a)
{
    int i;
    for (i = 0; i < (int)len; i++) {
        int bit = ((int)len - 1 - i) * 8;
        be[i] = (u8)(a->w[bit>>6] >> (bit & 63));
    }
}
static void bn_mulmod(bn *r, const bn *a, const bn *b, const bn *m)
{
    bn acc, tmp; int i, j;
    bn_zero(&acc);
    for (i = 0; i < BN_LIMBS; i++) {
        u64 carry = 0;
        if (!b->w[i]) continue;
        bn_zero(&tmp);
        for (j = 0; j + i < BN_LIMBS; j++) {
            unsigned __int128 p = (unsigned __int128)a->w[j] * b->w[i] + carry + tmp.w[j+i];
            tmp.w[j+i] = (u64)p;
            carry = (u64)(p >> 64);
        }
        { u64 c2 = 0; for (j = 0; j < BN_LIMBS; j++){
            unsigned __int128 s = (unsigned __int128)acc.w[j] + tmp.w[j] + c2;
            acc.w[j] = (u64)s; c2 = (u64)(s >> 64); } }
    }
    {
        bn rem, d; int bits = bn_bits(&acc), k;
        bn_zero(&rem); memcpy(&d, m, sizeof(bn));
        for (k = bits - 1; k >= 0; k--) {
            bn_shl1(&rem);
            rem.w[0] |= (u64)bn_bit(&acc, k);
            if (bn_cmp(&rem, &d) >= 0) bn_sub(&rem, &rem, &d);
        }
        memcpy(r, &rem, sizeof(bn));
    }
}
int bn_modexp(u8 *out, size_t outlen, const u8 *base, size_t blen,
              const u8 *exp, size_t elen, const u8 *mod, size_t mlen)
{
    bn b, e, m, acc; int i, bits;
    bn_from_bytes(&b, base, blen);
    bn_from_bytes(&e, exp, elen);
    bn_from_bytes(&m, mod, mlen);
    if (bn_is_zero(&m)) return EQ_ERR_ARG;
    bn_zero(&acc); acc.w[0] = 1;
    bits = bn_bits(&e);
    for (i = bits - 1; i >= 0; i--) {
        bn_mulmod(&acc, &acc, &acc, &m);
        if (bn_bit(&e, i)) bn_mulmod(&acc, &acc, &b, &m);
    }
    memset(out, 0, outlen);
    bn_to_bytes(out, outlen, &acc);
    return EQ_OK;
}
