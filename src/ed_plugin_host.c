#include "ed_plugin.h"
#include <string.h>

#ifdef _WIN32
#include <windows.h>

void *ed_plugin_open(const char *path)
{
    return (void *)LoadLibraryA(path);
}

void ed_plugin_close(void *h)
{
    if (h) FreeLibrary((HMODULE)h);
}

/* Ordinal-only loader: plugins import @1-@4 with names stripped, so the host
   must bind by ordinal, never by name. */
int ed_plugin_load(void *dll_handle, void **out_ordinals)
{
    static const WORD ords[4] = {1, 2, 3, 4};
    int i;
    if (!dll_handle || !out_ordinals) return EQ_ERR_ARG;
    memset(out_ordinals, 0, 4 * sizeof(void *));
    for (i = 0; i < 4; i++) {
        out_ordinals[i] = (void *)GetProcAddress((HMODULE)dll_handle, MAKEINTRESOURCEA(ords[i]));
        if (!out_ordinals[i]) return EQ_ERR_ARG;      /* partial ABI is a load failure */
    }
    return EQ_OK;
}
#else
void *ed_plugin_open(const char *path) { (void)path; return 0; }
void ed_plugin_close(void *h) { (void)h; }
int ed_plugin_load(void *dll_handle, void **out_ordinals)
{
    if (!dll_handle || !out_ordinals) return EQ_ERR_ARG;
    memset(out_ordinals, 0, 4 * sizeof(void *));
    return EQ_OK;
}
#endif

int ed_plugin_id_valid(u32 id)
{
    return (id >= ED_PLUGIN_ID_MIN) && ((id & 1) == 0);
}