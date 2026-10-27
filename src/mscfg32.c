#include "ed_config.h"
#include "ed_share2.h"
#include <string.h>

int ed_config_from_share2(const u8 *buf, size_t len)
{
    const ed_share2_hdr *h;
    if (len < sizeof(ed_share2_hdr)) return EQ_ERR_ARG;
    h = (const ed_share2_hdr *)buf;
    if (h->magic != ED_SHARE2_MAGIC) return EQ_ERR_ARG;
    /* TODO: carve share2.bin out of mscfg32.dll for the real layout */
    return EQ_OK;
}
