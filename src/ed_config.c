#include "ed_config.h"
#include "rc5.h"
#include <string.h>

/* Records are [type u16 BE][size u16 BE][value]. A record that overruns the
   buffer is an error, not a silent truncation: callers rely on the count. */
int EdConfigParse(const u8 *buf, size_t len, ed_record *out, size_t max)
{
    size_t off = 0, n = 0;
    if (!buf || !out) return EQ_ERR_ARG;
    while (off + 4 <= len) {
        u16 type = eq_get_be16(buf + off);
        u16 size = eq_get_be16(buf + off + 2);
        if (off + 4 + size > len) return EQ_ERR_ARG;
        if (n == max) return EQ_ERR_ARG;            /* caller's table too small */
        out[n].type = type;
        out[n].size = size;
        out[n].value = buf + off + 4;
        n++;
        off += 4 + size;
    }
    if (off != len) return EQ_ERR_ARG;              /* trailing partial header */
    return (int)n;
}

const ed_record *EdConfigFind(const ed_record *recs, size_t n, u16 type)
{
    size_t i;
    for (i = 0; i < n; i++) if (recs[i].type == type) return &recs[i];
    return NULL;
}

int EdConfigCryptRc5(u8 *buf, size_t len, const u8 *key, size_t keylen,
                        const u8 iv[8], int encrypt)
{
    rc5_ctx c;
    if (!buf || !key || !iv || len == 0 || (len % 8)) return EQ_ERR_ARG;
    if (rc5_init(&c, key, keylen) != EQ_OK) return EQ_ERR_CRYPTO;
    return encrypt ? rc5_cbc_encrypt(&c, iv, buf, len, buf)
                   : rc5_cbc_decrypt(&c, iv, buf, len, buf);
}

/* Serialize a record table back to [type u16 BE][size u16 BE][value] bytes.
   Returns the number of bytes written (or needed if out is NULL/cap too small). */
size_t EdConfigSerialize(const ed_record *recs, size_t n, u8 *out, size_t cap)
{
    size_t off = 0, i;
    for (i = 0; i < n; i++) {
        size_t need = 4 + recs[i].size;
        if (out && off + need <= cap) {
            eq_put_be16(out + off, recs[i].type);
            eq_put_be16(out + off + 2, recs[i].size);
            memcpy(out + off + 4, recs[i].value, recs[i].size);
        }
        off += need;
    }
    return off;
}