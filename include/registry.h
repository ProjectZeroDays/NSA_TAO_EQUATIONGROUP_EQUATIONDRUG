#ifndef REGISTRY_H
#define REGISTRY_H
#include "ed_plugin.h"

typedef enum {
    ED_REG_TARGET,
    ED_REG_PAYLOAD,
    ED_REG_CONFIG,
    ED_REG_STARTTIME,
    ED_REG_COUNT
} ed_reg_field;

int ed_reg_open(void);
int ed_reg_set(const char *logical, const u8 *val, u32 len);
int ed_reg_get(const char *logical, u8 *out, u32 cap, u32 *got);
int ed_reg_del(const char *logical);
const char *ed_reg_logical(ed_reg_field f);
#endif