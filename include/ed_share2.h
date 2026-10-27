#ifndef ED_SHARE2_H
#define ED_SHARE2_H
#include "eq_common.h"
#define ED_SHARE2_MAGIC 0x63959700u
#define ED_SHARE2_HDR   0x20
typedef struct { u32 magic; u32 size; u8 raw[ED_SHARE2_HDR]; } ed_share2_hdr;
int ed_config_from_share2(const u8 *buf, size_t len);
#endif
