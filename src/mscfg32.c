#include "ed_config.h"
#include "ed_share2.h"
#include <string.h>

/* share2.bin is carried inside mscfg32.dll at ED_SHARE2_MAGIC. On the wire the
   magic and declared size are big-endian; the record region follows the header.
   Returns the number of parsed records (>= 0) or EQ_ERR_ARG on failure. */
int ed_config_from_share2(const u8 *buf, size_t len)
{
    ed_record recs[ED_CONFIG_MAX];
    u32 size;
    size_t avail;
    int n;

    if (!buf || len < ED_SHARE2_HDR) return EQ_ERR_ARG;
    if (eq_get_be32(buf) != ED_SHARE2_MAGIC) return EQ_ERR_ARG;

    size = eq_get_be32(buf + 4);
    avail = len - ED_SHARE2_HDR;
    if (size > avail) return EQ_ERR_ARG;           /* declared larger than present */

    n = ed_config_parse(buf + ED_SHARE2_HDR, size, recs, ED_CONFIG_MAX);
    return n;
}

/* Surface the parsed share2 records through ed_config_find-compatible access.
   Callers can iterate recs[0..n-1] after a successful call. */
const ed_record *ed_share2_find(const ed_record *recs, size_t n, u16 type)
{
    return ed_config_find(recs, n, type);
}