#ifndef ED_RECORD_H
#define ED_RECORD_H
#include "eq_common.h"
typedef struct { u16 type; u16 size; const u8 *value; } ed_record;
#endif
