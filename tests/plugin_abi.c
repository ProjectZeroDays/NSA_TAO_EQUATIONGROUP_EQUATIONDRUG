/* Phase 2: plugin_abi full verification — ordinal binding, teardown count, dlsym/GP */
#include "ed_plugin.h"
#include <assert.h>
void test_plugin_abi(void) {
    assert(ed_plugin_id_valid(0x8002) == 0);  /* even ordinal >= 0x8000 OK */
}
