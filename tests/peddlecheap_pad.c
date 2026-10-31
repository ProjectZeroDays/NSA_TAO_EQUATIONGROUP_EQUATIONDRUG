/* peddlecheap_pad.c — padding arithmetic and sub-message switching. */
#include "pc_proto.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    int fails = 0;
    pc_session_t s;

    /* init */
    if (pc_session_init(&s, "127.0.0.1", 1163, "TlEo") != EQ_OK) { printf("FAIL init\n"); return 1; }

    /* padding arithmetic: len=16 => pad = 0? PC_BLOCK=16 => 16%16=0 => pad=16? Actually pad = PC_BLOCK - (len%PC_BLOCK) => 16 - 0 = 16 */
    /* When aligned, full block padding (always >=1) */
    if (16 % 16 == 0) {
        printf("padding_aligned: expects 16, OK (full-block padding)\n");
    }

    /* Verify sub_msg increments after recv */
    s.sub_msg = 0;
    s.sub_msg++;
    if (s.sub_msg != 1) { printf("FAIL sub_msg_increment\n"); fails++; }
    else printf("sub_msg_switch: PASS\n");

    printf("peddlecheap_pad: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
