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
int ed_plugin_load(void *dll_handle, void **out_ordinals, int *teardown_count)
{
    static const WORD ords[4] = {1, 2, 3, 4};
    int i;
    if (teardown_count) *teardown_count = 0;
    if (!dll_handle || !out_ordinals) return EQ_ERR_ARG;
    memset(out_ordinals, 0, 4 * sizeof(void *));
    for (i = 0; i < 4; i++) {
        out_ordinals[i] = (void *)GetProcAddress((HMODULE)dll_handle, MAKEINTRESOURCEA(ords[i]));
        if (!out_ordinals[i]) return EQ_ERR_ARG;
    }
    if (teardown_count) *teardown_count = 1;
    return EQ_OK;
}
#else
#include <dlfcn.h>

void *ed_plugin_open(const char *path)
{
    return (void *)dlopen(path, RTLD_NOW | RTLD_LOCAL);
}

void ed_plugin_close(void *h)
{
    if (h) dlclose(h);
}

/* Ordinal-only loader on POSIX: dlopen does not export by ordinal, so we
   synthesize ordinal binding by looking up exported symbols named
   "ordinal1".."ordinal4". Plugins built for this ABI export those names. */
int ed_plugin_load(void *dll_handle, void **out_ordinals, int *teardown_count)
{
    if (!dll_handle || !out_ordinals) return EQ_ERR_ARG;
    memset(out_ordinals, 0, 4 * sizeof(void *));
    if (teardown_count) *teardown_count = 0;
    for (int i = 0; i < 4; i++) {
        char sym[16];
        snprintf(sym, sizeof sym, "ordinal%d", i + 1);
        out_ordinals[i] = dlsym(dll_handle, sym);
        if (!out_ordinals[i]) return EQ_ERR_ARG;
    }
    if (teardown_count) *teardown_count = 1;
    return EQ_OK;
}
#endif

int ed_plugin_id_valid(u32 id)
{
    return (id >= ED_PLUGIN_ID_MIN) && ((id & 1) == 0);
}