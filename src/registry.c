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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ED_INI_PATH "~/.config/equationdrug/registry.ini"

static char *ini_path(void)
{
    const char *home = getenv("HOME");
    static char path[512];
    if (home) {
        snprintf(path, sizeof path, "%s/.config/equationdrug/registry.ini", home);
    } else {
        snprintf(path, sizeof path, ED_INI_PATH);
    }
    return path;
}

static int ini_ensure_dir(const char *path)
{
    char dir[512];
    strncpy(dir, path, sizeof dir - 1);
    char *slash = strrchr(dir, '/');
    if (slash) *slash = '\0';
    /* mkdir -p equivalent: try to create, ignore if exists */
    (void)mkdir(dir, 0700);
    return 0;
}

int ed_reg_open(void)
{
    ini_ensure_dir(ini_path());
    return EQ_OK;
}

int ed_reg_set(const char *logical, const u8 *val, u32 len)
{
    char name[41]; FILE *f;
    ed_reg_name(logical, name);
    ini_ensure_dir(ini_path());
    f = fopen(ini_path(), "a");
    if (!f) return EQ_ERR;
    fprintf(f, "[%s]\n", name);
    for (u32 i = 0; i < len; i++) fprintf(f, "%02x", val[i]);
    fprintf(f, "\n\n");
    fclose(f);
    return EQ_OK;
}

int ed_reg_get(const char *logical, u8 *out, u32 cap, u32 *got)
{
    char name[41]; FILE *f;
    char line[256];
    ed_reg_name(logical, name);
    f = fopen(ini_path(), "r");
    if (!f) return EQ_ERR;
    int in_section = 0;
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        /* strip newline */
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
        if (line[0] == '[' && line[strlen(line)-1] == ']') {
            line[strlen(line)-1] = '\0';
            in_section = (strcmp(line + 1, name) == 0);
            continue;
        }
        if (in_section && strlen(line) > 0) {
            /* hex pairs */
            size_t hexlen = strlen(line);
            size_t need = hexlen / 2;
            if (need > cap) { fclose(f); return EQ_ERR_ARG; }
            for (size_t i = 0; i < need; i++) {
                unsigned int v;
                sscanf(line + i * 2, "%2x", &v);
                out[i] = (u8)v;
            }
            if (got) *got = (u32)need;
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? EQ_OK : EQ_ERR;
}

int ed_reg_del(const char *logical)
{
    /* Not implemented for INI fallback: mark as error */
    (void)logical;
    return EQ_ERR;
}
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