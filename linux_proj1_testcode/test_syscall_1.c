#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef SYS_MY_GET_PHYSICAL
#define SYS_MY_GET_PHYSICAL 449
#endif

/* 呼叫核心裡的 syscall，回傳 PA 數字。PA 為 0 是題目允許的結果。 */
static uintptr_t get_pa(uintptr_t va)
{
    long result = syscall(SYS_MY_GET_PHYSICAL, va);

    if (result == -1) {
        fprintf(stderr, "syscall %d failed: %s\n", SYS_MY_GET_PHYSICAL,
                strerror(errno));
        fputs("Check the running kernel and the syscall number.\n", stderr);
        exit(EXIT_FAILURE);
    }

    return (uintptr_t)result;
}

static int check_pa(const char *label, uintptr_t pa, int expect_zero)
{
    int passed = expect_zero ? pa == 0 : pa != 0;

    printf("[%s] %s: PA = 0x%" PRIxPTR " (expected %s)\n",
           passed ? "PASS" : "FAIL", label, pa,
           expect_zero ? "0" : "non-zero");
    return !passed;
}

int main(void)
{
    /* 這個數字位在 x86-64 核心空間。測試只把它傳進 syscall。 */
    const uintptr_t kernel_va = (uintptr_t)UINT64_C(0xffff888000001000);
    long page_size = sysconf(_SC_PAGESIZE);
    void *page;
    uintptr_t va;
    int failures = 0;

    if (page_size <= 0) {
        fputs("Could not determine the page size.\n", stderr);
        return EXIT_FAILURE;
    }

    page = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }
    va = (uintptr_t)page;

    /* 先查剛配置的匿名區域。首次寫入前通常還沒有對應的實體頁面。 */
    failures += check_pa("1a. Anonymous page before first access", get_pa(va), 1);

    /* 寫入後再查同一個位址，確認測試的 syscall 確實能回傳實體位址。 */
    *(volatile unsigned char *)page = 0x5a;
    failures += check_pa("Control: same page after writing", get_pa(va), 0);

    if (munmap(page, (size_t)page_size) == -1) {
        perror("munmap");
        return EXIT_FAILURE;
    }
    failures += check_pa("1b. Same address after munmap", get_pa(va), 1);

    /* 傳入核心空間的位址數字，預期核心拒絕查詢。 */
    failures += check_pa("2. Kernel-space address", get_pa(kernel_va), 1);

    /* 致命訊號可能直接終止測試程序，這個分支須從核心端驗證。 */
    puts("[SKIP] 3. Interrupted lookup: requires kernel-side verification.");

    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
