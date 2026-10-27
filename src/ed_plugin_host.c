#include "ed_plugin.h"
#include <string.h>

/* Ordinal-only loader: plugins import @1-@4 with names stripped, so the host
   must bind by ordinal, never by name. */
int ed_plugin_load(void *dll_handle, void **out_ordinals)
{
    static const int ords[4] = {1, 2, 3, 4};
    int i;
    if (!dll_handle || !out_ordinals) return EQ_ERR_ARG;
    for (i = 0; i < 4; i++) {
        /* Windows: GetProcAddress((HMODULE)dll_handle, MAKEINTRESOURCE(ords[i])) */
        out_ordinals[i] = 0;
    }
    return EQ_OK;
}

int ed_plugin_id_valid(u32 id)
{
    return (id >= ED_PLUGIN_ID_MIN) && ((id & 1) == 0);
}
