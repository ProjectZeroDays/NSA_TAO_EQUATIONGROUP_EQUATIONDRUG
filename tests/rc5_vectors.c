#include "rc5.h"
#include <stdio.h>
int main(void)
{
    int rc = rc5_selftest();
    printf("rc5_selftest: %s (%d)\n", rc == EQ_OK ? "PASS" : "FAIL", rc);
    return rc == EQ_OK ? 0 : 1;
}
