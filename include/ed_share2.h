#ifndef ED_SHARE2_H
#define ED_SHARE2_H
#include "eq_common.h"
#include "ed_record.h"
#define ED_SHARE2_MAGIC 0x63959700u
#define ED_SHARE2_HDR   0x20                      /* total header bytes */
#define ED_SHARE2_BODY  (ED_SHARE2_HDR - 8)       /* payload after magic+size */
typedef struct { u32 magic; u32 size; u8 raw[ED_SHARE2_BODY]; } ed_share2_hdr;
int EdConfigFromShare2(const u8 *buf, size_t len);
int EdShare2Records(const u8 *buf, size_t len, ed_record *out, size_t max);
const ed_record *EdShare2Find(const ed_record *recs, size_t n, u16 type);
#endif