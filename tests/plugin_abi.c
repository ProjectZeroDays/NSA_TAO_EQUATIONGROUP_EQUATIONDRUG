#include "ed_plugin.h"
#include <stdio.h>
int ed_plugin_id_valid(int ord) { return (ord & 0x8000) && !(ord & 1); }
