#ifndef RC5_H
#define RC5_H
#include "eq_common.h"
#define RC5_ROUNDS 12
#define RC5_SUBWORDS (2 * (RC5_ROUNDS + 1))
typedef struct { u32 S[RC5_SUBWORDS]; int rounds; } rc5_ctx;
int  rc5_init(rc5_ctx *c, const u8 *key, size_t keylen);
void rc5_encrypt_block(const rc5_ctx *c, const u8 in[8], u8 out[8]);
void rc5_decrypt_block(const rc5_ctx *c, const u8 in[8], u8 out[8]);
int  rc5_cbc_encrypt(const rc5_ctx *c, const u8 iv[8], const u8 *in, size_t len, u8 *out);
int  rc5_cbc_decrypt(const rc5_ctx *c, const u8 iv[8], const u8 *in, size_t len, u8 *out);
int  rc5_selftest(void);
#endif
