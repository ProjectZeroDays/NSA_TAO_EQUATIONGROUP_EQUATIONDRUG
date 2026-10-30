#include "sha1.h"
#include <string.h>

#define ROL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_block(sha1_ctx *c, const u8 *p)
{
    u32 w[80], a, b, d, e, f, k, t; int i;
    for (i = 0; i < 16; i++)
        w[i] = ((u32)p[i*4] << 24) | ((u32)p[i*4+1] << 16) | ((u32)p[i*4+2] << 8) | p[i*4+3];
    for (i = 16; i < 80; i++) w[i] = ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    a = c->h[0]; b = c->h[1]; d = c->h[2]; e = c->h[3]; f = c->h[4];
    for (i = 0; i < 80; i++) {
        u32 tmp;
        if (i < 20)      { t = (b & d) | (~b & e); k = 0x5A827999; }
        else if (i < 40) { t = b ^ d ^ e;          k = 0x6ED9EBA1; }
        else if (i < 60) { t = (b & d) | (b & e) | (d & e); k = 0x8F1BBCDC; }
        else             { t = b ^ d ^ e;          k = 0xCA62C1D6; }
        tmp = ROL(a, 5) + t + f + k + w[i];
        f = e; e = d; d = ROL(b, 30); b = a; a = tmp;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += d; c->h[3] += e; c->h[4] += f;
}

void sha1_init(sha1_ctx *c)
{
    c->h[0] = 0x67452301; c->h[1] = 0xEFCDAB89; c->h[2] = 0x98BADCFE;
    c->h[3] = 0x10325476; c->h[4] = 0xC3D2E1F0;
    c->len = 0; c->bufn = 0;
}

void sha1_update(sha1_ctx *c, const u8 *p, size_t n)
{
    c->len += (u64)n * 8;
    while (n--) {
        c->buf[c->bufn++] = *p++;
        if (c->bufn == 64) { sha1_block(c, c->buf); c->bufn = 0; }
    }
}

void sha1_final(sha1_ctx *c, u8 out[20])
{
    u64 bits = c->len; int i;
    u8 pad = 0x80, zero = 0;
    sha1_update(c, &pad, 1);
    while (c->bufn != 56) sha1_update(c, &zero, 1);
    for (i = 7; i >= 0; i--) { u8 b = (u8)(bits >> (i * 8)); sha1_update(c, &b, 1); }
    for (i = 0; i < 20; i++) out[i] = (u8)(c->h[i >> 2] >> (24 - (i & 3) * 8));
}