#include "aes.h"
#include <stdio.h>
int main(void)
{
    int rc = aes_selftest();
    printf("aes_selftest: %s (%d)\n", rc == EQ_OK ? "PASS" : "FAIL", rc);
    return rc == EQ_OK ? 0 : 1;
}
