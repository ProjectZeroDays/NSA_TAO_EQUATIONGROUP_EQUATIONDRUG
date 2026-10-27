#include "pc_proto.h"
#include <stdio.h>
int main(void)
{
    int ok = 1;
    if (PC_HDR_IMPLANT + PC_BLOCK != 24) { printf("24-byte invariant broken\n"); ok = 0; }
    if (PC_HDR_LP != 16) { printf("LP header size wrong\n"); ok = 0; }
    if (PC_BLOB_LEN != 36) { printf("blob size wrong\n"); ok = 0; }
    if (PC_BLOB_OFF_SENDSIZE != 24 || PC_BLOB_OFF_CHECKSUM != 28 || PC_BLOB_OFF_FLAGS != 32) {
        printf("blob offsets drifted\n"); ok = 0;
    }
    printf("pc_selftest: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
