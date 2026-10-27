#include "eq_common.h"
u16 eq_get_be16(const u8 *p){ return (u16)((p[0] << 8) | p[1]); }
u32 eq_get_be32(const u8 *p){ return ((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|p[3]; }
u32 eq_get_le32(const u8 *p){ return ((u32)p[3]<<24)|((u32)p[2]<<16)|((u32)p[1]<<8)|p[0]; }
void eq_put_be16(u8 *p, u16 v){ p[0]=(u8)(v>>8); p[1]=(u8)v; }
void eq_put_be32(u8 *p, u32 v){ p[0]=(u8)(v>>24); p[1]=(u8)(v>>16); p[2]=(u8)(v>>8); p[3]=(u8)v; }
void eq_put_le32(u8 *p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
