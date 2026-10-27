#ifndef AES_H
#define AES_H
#include "eq_common.h"
typedef struct { u8 rk[176]; int nr; } aes_ctx;
int  aes128_init(aes_ctx *c, const u8 key[16]);
void aes128_encrypt_block(const aes_ctx *c, const u8 in[16], u8 out[16]);
void aes128_decrypt_block(const aes_ctx *c, const u8 in[16], u8 out[16]);
int  aes128_cbc_encrypt(const aes_ctx *c, u8 iv[16], const u8 *in, size_t len, u8 *out);
int  aes128_cbc_decrypt(const aes_ctx *c, u8 iv[16], const u8 *in, size_t len, u8 *out);
int  aes_selftest(void);
#endif
