#include "pc_proto.h"
#include "eq_common.h"
#include "aes.h"
#include "bignum.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#define PC_CLOSE closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define PC_CLOSE close
#endif

void pc_set_timeouts(int sock, int ms) { (void)sock; (void)ms; }
void pc_random(u8 *out, size_t len) { memset(out, 0xAA, len); }
void pc_build_hello(u8 out[PC_HELLO_LEN], const pc_session_t *s) {
    memset(out, 0, PC_HELLO_LEN);
    out[0] = 0xFE; out[1] = PC_VER_MAJOR; out[2] = PC_VER_SUB;
    out[3] = PC_VER_MINOR; out[4] = PC_VER_BUILD;
}
int pc_session_init(pc_session_t *s, const char *ip, u16 port, const char *hdr) {
    memset(s, 0, sizeof(*s)); strncpy(s->lp_ip, ip, sizeof(s->lp_ip)-1); s->lp_port = port; s->sock = PC_INVALID_SOCK; s->timeout_ms = 5000; strncpy(s->hdr_name, hdr ? hdr : "TlEo", sizeof(s->hdr_name)-1); return EQ_OK;
}
const char *eq_strerror(int rc) { return rc == EQ_OK ? "OK" : (rc == EQ_MORE ? "MORE" : "ERR"); }
int pc_handshake_begin(pc_session_t *s) { s->crypto_on = 1; return EQ_OK; }
int pc_handshake_step(pc_session_t *s, const u8 *pubkey, size_t pubkey_len,
                      u8 *exe_out, size_t exe_cap, size_t *exe_len) {
    (void)s; (void)pubkey; (void)pubkey_len; (void)exe_out; (void)exe_cap; (void)exe_len;
    return EQ_OK;
}
int pc_handshake(pc_session_t *s, const u8 *pubkey, size_t pubkey_len,
                  u8 *exe_out, size_t exe_cap, size_t *exe_len) {
    (void)s; (void)pubkey; (void)pubkey_len; (void)exe_out; (void)exe_cap; (void)exe_len;
    return EQ_OK;
}
