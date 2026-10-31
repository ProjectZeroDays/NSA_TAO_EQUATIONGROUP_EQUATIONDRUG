#include "ed_plugin.h"
#include "ed_config.h"
#include "registry.h"
#include "sha1.h"
#include <string.h>
#include <stdio.h>

/* Value names are SHA1-derived, so no readable strings survive in the binary.
   Callers pass the logical name; ed_reg_name maps it to 40 hex chars. */

static void ed_reg_name(const char *logical, char out[41])
{
    static const char HEX[] = "0123456789abcdef";
    u8 d[20]; sha1_ctx c; int i;
    sha1_init(&c);
    sha1_update(&c, (const u8 *)logical, strlen(logical));
    sha1_final(&c, d);
    for (i = 0; i < 20; i++) { out[i * 2] = HEX[d[i] >> 4]; out[i * 2 + 1] = HEX[d[i] & 15]; }
    out[40] = '\0';
}

#ifdef _WIN32
#include <windows.h>
#define ED_ROOT "Software\\MemSubSys\\1"

int ed_reg_open(void)
{
    HKEY k;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, ED_ROOT, 0, NULL, 0,
                        KEY_ALL_ACCESS, NULL, &k, NULL) != ERROR_SUCCESS) return EQ_ERR;
    RegCloseKey(k);
    return EQ_OK;
}

int ed_reg_set(const char *logical, const u8 *val, u32 len)
{
    char name[41]; HKEY k; LONG rc;
    ed_reg_name(logical, name);
    if (RegCreateKeyExA(HKEY_CURRENT_USER, ED_ROOT, 0, NULL, 0, KEY_ALL_ACCESS,
                        NULL, &k, NULL) != ERROR_SUCCESS) return EQ_ERR;
    rc = RegSetValueExA(k, name, 0, REG_BINARY, val, len);
    RegCloseKey(k);
    return rc == ERROR_SUCCESS ? EQ_OK : EQ_ERR;
}

int ed_reg_get(const char *logical, u8 *out, u32 cap, u32 *got)
{
    char name[41]; HKEY k; DWORD type = 0, n = cap; LONG rc;
    ed_reg_name(logical, name);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, ED_ROOT, 0, KEY_READ, &k) != ERROR_SUCCESS) return EQ_ERR;
    rc = RegQueryValueExA(k, name, NULL, &type, out, &n);
    RegCloseKey(k);
    if (rc != ERROR_SUCCESS || type != REG_BINARY) return EQ_ERR;
    if (got) *got = (u32)n;
    return EQ_OK;
}

int ed_reg_del(const char *logical)
{
    char name[41]; HKEY k; LONG rc;
    ed_reg_name(logical, name);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, ED_ROOT, 0, KEY_ALL_ACCESS, &k) != ERROR_SUCCESS) return EQ_ERR;
    rc = RegDeleteValueA(k, name);
    RegCloseKey(k);
    return rc == ERROR_SUCCESS ? EQ_OK : EQ_ERR;
}
#else
int ed_reg_open(void) { return EQ_OK; }
int ed_reg_set(const char *l, const u8 *v, u32 n) { (void)l; (void)v; (void)n; return EQ_ERR; }
int ed_reg_get(const char *l, u8 *o, u32 c, u32 *g) { (void)l; (void)o; (void)c; (void)g; return EQ_ERR; }
int ed_reg_del(const char *l) { (void)l; return EQ_ERR; }
#endif

const char *ed_reg_logical(ed_reg_field f)
{
    switch (f) {
    case ED_REG_TARGET:      return "Target";
    case ED_REG_PAYLOAD:     return "Payload";
    case ED_REG_CONFIG:      return "Configuration";
    case ED_REG_STARTTIME:   return "StartTime";
    default:                 return "?";
    }
}