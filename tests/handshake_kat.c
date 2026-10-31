/* handshake_kat.c - end-to-end pc_handshake validation against a mock LP.
 *
 * On POSIX: spawns harness/mock_lp.py on a loopback port, then runs
 * pc_handshake against it and validates every step completes with correct
 * framing. On Windows: performs a compile/link smoke test only (the mock
 * LP test requires fork()).
 *
 * The mock LP never decrypts (no private key), so it validates header
 * shape, clear/pad arithmetic and sub-message header switching.
 */
#include "pc_proto.h"
#include "aes.h"
#include "bignum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define MOCK_LP "harness/mock_lp.py"
#define PORT_FILE "/tmp/pc_handshake_port"
#define EXE_CAP (1 << 20)

/* Build a minimal RSA public key blob: [modlen u32 BE][mod bytes][exp bytes].
   For the test we use modlen=4 (modulus=65537=0x10001, exp=65537=0x10001). */
static int build_test_pubkey(u8 *out, size_t cap)
{
    u8 mod_be[4] = {0x00, 0x01, 0x00, 0x01};   /* modulus = 65537 */
    u8 exp_be[4] = {0x00, 0x01, 0x00, 0x01};   /* e = 65537 */
    if (4 + 4 + 4 > cap) return -1;
    eq_put_be32(out, 4);                    /* modlen = 4 */
    memcpy(out + 4, mod_be, 4);             /* modulus */
    memcpy(out + 8, exp_be, 4);             /* exponent */
    return 12;
}

#ifdef _WIN32
/* Windows: compile/link smoke test only */
int main(void)
{
    pc_session_t s;
    u8 pubkey[PC_PUBKEY_LEN];
    u8 exe_buf[EXE_CAP];
    size_t exe_len = 0;
    int pklen;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("FAIL: WSAStartup\n");
        return 1;
    }

    pklen = build_test_pubkey(pubkey, sizeof pubkey);
    if (pklen < 0) {
        printf("FAIL: could not build test public key\n");
        return 1;
    }

    /* Verify pc_session_init works */
    if (pc_session_init(&s, "127.0.0.1", 1163, "TlEo") != EQ_OK) {
        printf("FAIL: pc_session_init\n");
        WSACleanup();
        return 1;
    }

    WSACleanup();
    printf("handshake_kat: PASS (Windows smoke test)\n");
    return 0;
}
#else
/* POSIX: full end-to-end test against mock_lp.py */

static int spawn_mock_lp(pid_t *pid)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    *pid = fork();
    if (*pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execlp("python3", "python3", MOCK_LP, "--port-file", PORT_FILE,
               "--timeout", "20.0", (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    return pipefd[0];
}

static int read_port_from_file(void)
{
    FILE *f = fopen(PORT_FILE, "r");
    if (!f) return -1;
    int port = 0;
    fscanf(f, "%d", &port);
    fclose(f);
    return port;
}

int main(void)
{
    pid_t lp_pid;
    int pipefd, status;
    int port, fails = 0;
    pc_session_t s;
    u8 pubkey[PC_PUBKEY_LEN];
    u8 exe_buf[EXE_CAP];
    size_t exe_len = 0;

    unlink(PORT_FILE);

    pipefd = spawn_mock_lp(&lp_pid);
    if (pipefd < 0) {
        printf("FAIL: could not spawn mock_lp\n");
        return 1;
    }

    /* Wait for the port file to appear */
    port = -1;
    for (int i = 0; i < 100; i++) {
        port = read_port_from_file();
        if (port > 0) break;
        usleep(100000); /* 100ms */
    }
    if (port <= 0) {
        printf("FAIL: mock_lp did not write port file\n");
        kill(lp_pid, SIGKILL);
        waitpid(lp_pid, &status, 0);
        close(pipefd);
        return 1;
    }
    printf("mock_lp listening on port %d\n", port);

    /* Read mock_lp stdout (discard) */
    { char dummy[256]; while (read(pipefd, dummy, sizeof dummy) > 0) { } }
    close(pipefd);

    /* Build test public key */
    int pklen = build_test_pubkey(pubkey, sizeof pubkey);
    if (pklen < 0) {
        printf("FAIL: could not build test public key\n");
        kill(lp_pid, SIGKILL);
        waitpid(lp_pid, &status, 0);
        return 1;
    }

    /* Initialize session and run handshake */
    if (pc_session_init(&s, "127.0.0.1", (u16)port, "TlEo") != EQ_OK) {
        printf("FAIL: pc_session_init\n");
        kill(lp_pid, SIGKILL);
        waitpid(lp_pid, &status, 0);
        return 1;
    }

    int rc = pc_handshake(&s, pubkey, (size_t)pklen, exe_buf, EXE_CAP, &exe_len);
    if (rc != EQ_OK) {
        printf("FAIL: pc_handshake returned %d\n", rc);
        kill(lp_pid, SIGKILL);
        waitpid(lp_pid, &status, 0);
        return 1;
    }

    printf("handshake: OK (exe_len=%zu)\n", exe_len);

    /* Clean up mock_lp */
    kill(lp_pid, SIGTERM);
    waitpid(lp_pid, &status, 0);

    unlink(PORT_FILE);

    printf("handshake_kat: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
#endif