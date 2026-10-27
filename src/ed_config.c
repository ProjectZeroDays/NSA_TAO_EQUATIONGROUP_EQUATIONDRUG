#include "ed_config.h"
#include "rc5.h"
#include <string.h>

int ed_config_parse(const u8 *buf, size_t len, ed_record *out, size_t max)
{
    size_t off = 0, n = 0;
    while (off + 4 <= len && n < max) {
        u16 type = eq_get_be16(buf + off);
        u16 size = eq_get_be16(buf + off + 2);
        if (off + 4 + size > len) break;
        out[n].type = type;
        out[n].size = size;
        out[n].value = buf + off + 4;
        n++;
        off += 4 + size;
    }
    return (int)n;
}

int ed_config_crypt_rc5(u8 *buf, size_t len, const u8 *key, size_t keylen)
{
    rc5_ctx c;
    u8 iv[8] = {0};
    if (len % 8) return EQ_ERR_ARG;
    if (rc5_init(&c, key, keylen) != EQ_OK) return EQ_ERR_CRYPTO;
    return rc5_cbc_decrypt(&c, iv, buf, len, buf);
}
