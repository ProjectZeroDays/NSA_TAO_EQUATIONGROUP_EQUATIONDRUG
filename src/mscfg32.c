#include "ed_config.h"
#include "ed_share2.h"
#include <string.h>
int EdConfigParse(const u8 *buf, size_t len, ed_record *out, size_t max);
const ed_record *EdConfigFind(const ed_record *recs, size_t n, u16 type);

/* share2.bin is carried inside mscfg32.dll at ED_SHARE2_MAGIC. On the wire the
   magic and declared size are big-endian; the record region follows the header.
   Returns the number of parsed records (>= 0) or EQ_ERR_ARG on failure. */
int EdConfigFromShare2(const u8 *buf, size_t len)
{
    ed_record recs[PCHEAP_CONFIG_MAX];
    u32 size;
    size_t avail;
    int n;

    if (!buf || len < ED_SHARE2_HDR) return EQ_ERR_ARG;
    if (eq_get_be32(buf) != ED_SHARE2_MAGIC) return EQ_ERR_ARG;

    size = eq_get_be32(buf + 4);
    avail = len - ED_SHARE2_HDR;
    if (size > avail) return EQ_ERR_ARG;           /* declared larger than present */

    n = EdConfigParse(buf + ED_SHARE2_HDR, size, recs, PCHEAP_CONFIG_MAX);
    return n;
}

/* Surface parsed records to caller (fix item 3). */
int EdShare2Records(const u8 *buf, size_t len, ed_record *out, size_t max)
{
    ed_record local_recs[PCHEAP_CONFIG_MAX];
    int n = EdConfigParse(buf + ED_SHARE2_HDR, eq_get_be32(buf + 4),
                            local_recs, PCHEAP_CONFIG_MAX);
    if (n < 0) return n;
    if (out && max > 0) {
        size_t cp = (size_t)n < max ? (size_t)n : max;
        memcpy(out, local_recs, sizeof(ed_record) * cp);
    }
    return n;
}

/* Surface the parsed share2 records through EdConfigFind-compatible access.
   Callers can iterate recs[0..n-1] after a successful call. */
const ed_record *EdShare2Find(const ed_record *recs, size_t n, u16 type)
{
    return EdConfigFind(recs, n, type);
}
int EdConfigLoad(const char *path) { (void)path; return EQ_OK; }
int EdPluginHostEnumerate(const char *dir, int *ids, size_t max) { (void)dir; (void)ids; (void)max; return 0; }