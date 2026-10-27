#ifndef ED_CONFIG_H
#define ED_CONFIG_H
#include "eq_common.h"
#define ED_MUTEX "{01C482BA-BD31-4874-A08B-A93EA5BCE511}"
#define ED_EVENT "{D0385CB7-B834-45D1-A501-1A1700E6C34E}"
#define ED_LOGFILE "~yh56816.tmp"
typedef struct { u16 type; u16 size; const u8 *value; } ed_record;
int ed_config_parse(const u8 *buf, size_t len, ed_record *out, size_t max);
int ed_config_crypt_rc5(u8 *buf, size_t len, const u8 *key, size_t keylen);
#endif
