// #include<ulib.h>

// int main(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
// {
// 	printf("Hello World!\n");
// 	return 0;
// }

#include <ulib.h>

int main(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
    // 1) First mapping: 22 bytes, read/write
    char *addr1 = mmap(NULL, 22, PROT_READ|PROT_WRITE, 0);
    if ((long)addr1 < 0) {
        printf("TEST CASE FAILED: mmap1\n");
        return 1;
    }
    // Should see 1 VMA, size rounded to 4096B.
    pmap(1);

    // 2) Second mapping: 4096 bytes, read-only
    char *addr2 = mmap(NULL, 4096, PROT_READ, 0);
    if ((long)addr2 < 0) {
        printf("TEST CASE FAILED: mmap2\n");
        return 1;
    }
    // Now 2 VMAs (different prot).
    pmap(1);

    // 3) Unmap the second VMA
    if (munmap(addr2, 4096) < 0) {
        printf("TEST CASE FAILED: munmap1\n");
        return 1;
    }
    // Back to 1 VMA
    pmap(1);

    // 4) Unmap the first VMA
    if (munmap(addr1, 22) < 0) {
        printf("TEST CASE FAILED: munmap2\n");
        return 1;
    }
    // Now 0 VMAs
    pmap(1);

    printf("ALL TESTS PASSED\n");
    return 0;
}
