/* Ordinal-only plugin template. Names are irrelevant at link time; the
   ordinals in def/ed_plugin.def are the ABI. */
#include "ed_plugin.h"

u32 ed_ordinal1(void) { return ED_PLUGIN_ID_MIN; }
u32 ed_ordinal2(void *cfg, u32 cfg_len) { (void)cfg; (void)cfg_len; return 0; }
u32 ed_ordinal3(void *in, u32 in_len, void *out, u32 out_cap)
{
    (void)in; (void)in_len; (void)out; (void)out_cap; return 0;
}
void ed_ordinal4(void) { }
