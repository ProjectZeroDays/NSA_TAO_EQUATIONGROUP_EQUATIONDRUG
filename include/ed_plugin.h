#ifndef ED_PLUGIN_H
#define ED_PLUGIN_H
#include "eq_common.h"

/* Ordinal-only ABI. Every plugin exports these four, names stripped.
   def/ed_plugin.def freezes ordinals 1-4 with NONAME. */
typedef u32 (*ed_ordinal1_fn)(void);
typedef u32 (*ed_ordinal2_fn)(void *cfg, u32 cfg_len);
typedef u32 (*ed_ordinal3_fn)(void *in, u32 in_len, void *out, u32 out_cap);
typedef void (*ed_ordinal4_fn)(void);

#define ED_PLUGIN_ID_MIN 0x8000
#define ED_REG_KEY "MemSubSys\\1"

void *ed_plugin_open(const char *path);
void ed_plugin_close(void *h);
int ed_plugin_load(void *dll_handle, void **out_ordinals);
#endif
