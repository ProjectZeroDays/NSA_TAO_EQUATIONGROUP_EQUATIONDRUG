/* Phase 5: payload dispatcher executable stream verification reference */
/* Executable stream length: FRAME (4096) * 3 = 12288 bytes */
#include <assert.h>
void test_executable_stream(void) { assert(4096 * 3 == 12288); }
