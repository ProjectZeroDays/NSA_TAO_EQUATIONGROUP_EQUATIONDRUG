#include "rc5.h"
#include <string.h>
#define P32 0xB7E15163u
#define Q32 0x9E3779B9u
static u32 rotl(u32 x, u32 n){ return (x << (n & 31)) | (x >> ((32 - n) & 31)); }
static u32 rotr(u32 x, u32 n){ return (x >> (n & 31)) | (x << ((32 - n) & 31)); }

int rc5_init(rc5_ctx *c, const u8 *key, size_t keylen)
{
    u32 L[64]; int i, j, k, t, u;
    if (!c || !key || keylen == 0 || keylen > 256) return EQ_ERR_ARG;
    c->rounds = RC5_ROUNDS;
    u = (int)((keylen + 3) / 4);
    for (i = 0; i < u; i++) {
        u32 v = 0; int n = (int)keylen - i * 4;
        if (n > 4) n = 4;
        for (j = 0; j < n; j++) v |= (u32)key[i * 4 + j] << (8 * j);
        L[i] = v;
    }
    c->S[0] = P32;
    for (i = 1; i < RC5_SUBWORDS; i++) c->S[i] = c->S[i-1] + Q32;
    i = j = 0; t = RC5_SUBWORDS > u ? RC5_SUBWORDS : u;
    { u32 A = 0, B = 0;
      for (k = 0; k < 3 * t; k++) {
          A = c->S[i] = rotl(c->S[i] + A + B, 3);
          B = L[j] = rotl(L[j] + A + B, A + B);
          i = (i + 1) % RC5_SUBWORDS; j = (j + 1) % u;
      } }
    return EQ_OK;
}

void rc5_encrypt_block(const rc5_ctx *c, const u8 in[8], u8 out[8])
{
    u32 A = (u32)in[0] | ((u32)in[1]<<8) | ((u32)in[2]<<16) | ((u32)in[3]<<24);
    u32 B = (u32)in[4] | ((u32)in[5]<<8) | ((u32)in[6]<<16) | ((u32)in[7]<<24);
    int i;
    A += c->S[0]; B += c->S[1];
    for (i = 1; i <= c->rounds; i++) {
        A = rotl(A ^ B, B) + c->S[2*i];
        B = rotl(B ^ A, A) + c->S[2*i + 1];
    }
    out[0]=(u8)A; out[1]=(u8)(A>>8); out[2]=(u8)(A>>16); out[3]=(u8)(A>>24);
    out[4]=(u8)B; out[5]=(u8)(B>>8); out[6]=(u8)(B>>16); out[7]=(u8)(B>>24);
}

void rc5_decrypt_block(const rc5_ctx *c, const u8 in[8], u8 out[8])
{
    u32 A = (u32)in[0] | ((u32)in[1]<<8) | ((u32)in[2]<<16) | ((u32)in[3]<<24);
    u32 B = (u32)in[4] | ((u32)in[5]<<8) | ((u32)in[6]<<16) | ((u32)in[7]<<24);
    int i;
    for (i = c->rounds; i >= 1; i--) {
        B = rotr(B - c->S[2*i + 1], A) ^ A;
        A = rotr(A - c->S[2*i], B) ^ B;
    }
    B -= c->S[1]; A -= c->S[0];
    out[0]=(u8)A; out[1]=(u8)(A>>8); out[2]=(u8)(A>>16); out[3]=(u8)(A>>24);
    out[4]=(u8)B; out[5]=(u8)(B>>8); out[6]=(u8)(B>>16); out[7]=(u8)(B>>24);
}

int rc5_cbc_encrypt(const rc5_ctx *c, const u8 iv[8], const u8 *in, size_t len, u8 *out)
{
    u8 prev[8]; size_t i, j;
    if (len % 8) return EQ_ERR_ARG;
    memcpy(prev, iv, 8);
    for (i = 0; i < len; i += 8) {
        u8 blk[8];
        for (j = 0; j < 8; j++) blk[j] = in[i+j] ^ prev[j];
        rc5_encrypt_block(c, blk, out + i);
        memcpy(prev, out + i, 8);
    }
    return EQ_OK;
}

int rc5_cbc_decrypt(const rc5_ctx *c, const u8 iv[8], const u8 *in, size_t len, u8 *out)
{
    u8 prev[8], cur[8]; size_t i, j;
    if (len % 8) return EQ_ERR_ARG;
    memcpy(prev, iv, 8);
    for (i = 0; i < len; i += 8) {
        memcpy(cur, in + i, 8);
        rc5_decrypt_block(c, cur, out + i);
        for (j = 0; j < 8; j++) out[i+j] ^= prev[j];
        memcpy(prev, cur, 8);
    }
    return EQ_OK;
}

struct vec { u8 key[16]; u8 pt[8]; u8 ct[8]; };
static const struct vec V[] = {
  {{0}, {0}, {0xEE,0xDB,0xA5,0x21,0x6D,0x8F,0x4B,0x15}},
  {{0x91,0x5F,0x46,0x19,0xBE,0x41,0xB2,0x51,0x63,0x55,0xA5,0x01,0x10,0xA9,0xCE,0x91},
   {0}, {0xF7,0xC0,0x13,0xAC,0x5B,0x79,0xFB,0x64}},
  {{0x91,0x5F,0x46,0x19,0xBE,0x41,0xB2,0x51,0x63,0x55,0xA5,0x01,0x10,0xA9,0xCE,0x91},
   {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, {0x41,0xE5,0xC5,0xA8,0x5A,0x0A,0xF5,0xD2}},
  {{0x78,0x33,0x48,0xE7,0x5A,0xEB,0x0F,0x2F,0xD7,0xB1,0x69,0xBB,0x8D,0xC1,0x67,0x87},
   {0}, {0x2F,0x42,0xB3,0xB7,0x03,0x95,0x0E,0x6A}},
};

int rc5_selftest(void)
{
    rc5_ctx c; u8 out[8]; size_t i;
    for (i = 0; i < sizeof(V)/sizeof(V[0]); i++) {
        if (rc5_init(&c, V[i].key, 16) != EQ_OK) return -1;
        rc5_encrypt_block(&c, V[i].pt, out);
        if (memcmp(out, V[i].ct, 8)) return -(int)(i + 1);
    }
    return EQ_OK;
}
