#ifndef SHA1_H
#define SHA1_H
#include "eq_common.h"

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct {
    u32 h[5];
    u64 len;
    u8 buf[SHA1_BLOCK_SIZE];
    size_t bufn;
} sha1_ctx;

void sha1_init(sha1_ctx *c);
void sha1_update(sha1_ctx *c, const u8 *p, size_t n);
void sha1_final(sha1_ctx *c, u8 out[SHA1_DIGEST_SIZE]);

#endif