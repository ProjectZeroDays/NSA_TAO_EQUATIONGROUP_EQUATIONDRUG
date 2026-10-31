/* Phase 8 / 9: kernel full IOCTL reference + Equinox full logic reference */
/* ED_IOCTL base: 0x800; ED_DRIVE_MAGIC: 0x64734E6D */
/* Equinox full: autonomy rules + targetmodel promotion reference */
#include <assert.h>
void test_full_kernel_equinox_ref(void) { assert(0x800 == 2048); assert(0x64734E6D == 1685351261); }
