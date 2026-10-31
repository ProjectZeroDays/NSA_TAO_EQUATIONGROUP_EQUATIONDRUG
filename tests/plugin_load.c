/* plugin_load.c — plugin host ordinal binding smoke test. */
#include "ed_plugin.h"
#include "eq_common.h"
#include <stdio.h>

int main(void)
{
    int fails = 0;
    void *h = 0;
    void *ords[4];

    /* Invalid handle must return EQ_ERR_ARG */
    if (ed_plugin_load(0, ords) != EQ_ERR_ARG) { printf("FAIL load_null_handle\n"); fails++; }
    else printf("load_null_handle: PASS\n");

    printf("plugin_load: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
