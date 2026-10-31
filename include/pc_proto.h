#ifndef PC_PROTO_H
#define PC_PROTO_H
#include "eq_common.h"

#define PC_HDR_IMPLANT 8
#define PC_HDR_LP      16
#define PC_BLOCK       16
#define PC_MAX_BODY    0x10000

#define PC_BLOB_LEN          36
#define PC_BLOB_OFF_LIBTYPE  16
#define PC_BLOB_OFF_UNK20    20
#define PC_BLOB_OFF_SENDSIZE 24
#define PC_BLOB_OFF_CHECKSUM 28
#define PC_BLOB_OFF_RUNTYPE  30
#define PC_BLOB_OFF_FLAGS    32
#define PC_BLOB_OFF_TAIL     34

#define PC_RUN_EGG     1
#define PC_RUN_MEMLIB  2
#define PC_RUN_FILELIB 3
#define PC_RUN_EXE     4

#define PC_ARCH_X64       8
#define PC_PLATFORM_WINNT 1
#define PC_HELLO_LEN      48
#define PC_RSA_LEN        256
#define PC_PUBKEY_LEN     516

#define PC_INVALID_SOCK (-1)
typedef int pc_sock_t;

typedef struct {
    char      lp_ip[16];
    u16       lp_port;
    char      hdr_name[8];
    u32       connid;
    u32       conn_counter;
    u32       seq;
    u32       lp_seq;
    u8        session_key[16];
    u8        iv[16];
    int       crypto_on;
    int       sub_msg;
    u32       timeout_ms;
    u8        ptbuf[PC_MAX_BODY];   /* per-session plaintext buffer (Commit 12) */
    pc_sock_t sock;
} pc_session_t;

int pc_session_init(pc_session_t *s, const char *ip, u16 port, const char *hdr);
int pc_reconnect(pc_session_t *s);
int pc_build_header(char *out, size_t cap, const pc_session_t *s, u32 body_len);
int pc_send(pc_session_t *s, const u8 *payload, u32 len);
int pc_recv(pc_session_t *s, u8 *out, u32 cap, u32 *out_len);
int pc_handshake(pc_session_t *s, const u8 *pubkey, size_t pubkey_len,
                 u8 *exe_out, size_t exe_cap, size_t *exe_len);
#define PC_VER_MAJOR 2
#define PC_VER_SUB 3
#define PC_VER_MINOR 0
#define PC_VER_BUILD 0
int pc_handshake_begin(pc_session_t *s);
int pc_handshake_step(pc_session_t *s, const u8 *pubkey, size_t pubkey_len,
                      u8 *exe_out, size_t exe_cap, size_t *exe_len);
#endif
