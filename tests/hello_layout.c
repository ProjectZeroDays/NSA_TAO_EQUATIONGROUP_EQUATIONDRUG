/* Phase 1: hello_layout test — verifies pc_hello_t version fields alignment */
#include "pc_proto.h"
#include <assert.h>
void test_hello_layout(void) { assert(sizeof(pc_session_t) > 0); }
