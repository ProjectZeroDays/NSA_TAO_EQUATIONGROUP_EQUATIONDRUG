#ifndef EQ_COMMON_H
#define EQ_COMMON_H
#include <stdint.h>
#include <stddef.h>

typedef uint8_t  u8;  typedef uint16_t u16;
typedef uint32_t u32; typedef uint64_t u64;

#define EQ_OK 0
#define EQ_ERR -1
#define EQ_ERR_ARG -2
#define EQ_ERR_CRYPTO -3
#define EQ_ERR_IO -4

u16  eq_get_be16(const u8 *p);
u32  eq_get_be32(const u8 *p);
u32  eq_get_le32(const u8 *p);
void eq_put_be16(u8 *p, u16 v);
void eq_put_be32(u8 *p, u32 v);
void eq_put_le32(u8 *p, u32 v);
#endif
