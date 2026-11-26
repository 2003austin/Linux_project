#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_MY_GET_PHYSICAL
#define SYS_MY_GET_PHYSICAL 449
#endif

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

enum test_result { TEST_PASS, TEST_FAIL, TEST_SKIP };
enum { INTERRUPT_OFFSET = 100 };

static const size_t pmd_size = 2UL * 1024 * 1024;
static const size_t pud_size = 1024UL * 1024 * 1024;

struct summary {
    unsigned int passed;
    unsigned int failed;
    unsigned int skipped;
};

static void report(struct summary *summary, enum test_result result,
                   const char *name, const char *detail)
{
    if (result == TEST_PASS) {
        ++summary->passed;
        printf("[PASS] %s", name);
    } else if (result == TEST_FAIL) {
        ++summary->failed;
        printf("[FAIL] %s", name);
    } else {
        ++summary->skipped;
        printf("[SKIP] %s", name);
    }
    if (detail)
        printf(" (%s)", detail);
    putchar('\n');
}

static uint64_t get_pa(uintptr_t va)
{
    long pa = syscall(SYS_MY_GET_PHYSICAL, va, 0UL, 0UL, 0UL, 0UL, 0UL);

    if (pa == -1) {
        fprintf(stderr, "syscall %d: %s. Check the booted kernel and syscall number.\n",
                SYS_MY_GET_PHYSICAL, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return (uint64_t)pa;
}

static void expect_zero(struct summary *summary, const char *name, uintptr_t va)
{
    uint64_t pa = get_pa(va);
    char detail[64];

    snprintf(detail, sizeof(detail), "PA = 0x%" PRIx64 ", expected 0", pa);
    report(summary, pa == 0 ? TEST_PASS : TEST_FAIL, name, detail);
}

/* 從 pagemap 取得獨立的實體位址。沒有權限時，核心可能把 PFN 欄位清成 0。 */
static uint64_t pagemap_pa(int fd, uintptr_t va, size_t page_size)
{
    uint64_t entry;
    uint64_t pfn;
    off_t entry_offset = (off_t)(va / page_size) * sizeof(entry);

    if (fd < 0 || pread(fd, &entry, sizeof(entry), entry_offset) != (ssize_t)sizeof(entry))
        return 0;
    if (!(entry & (UINT64_C(1) << 63)))
        return 0;
    pfn = entry & ((UINT64_C(1) << 55) - 1);
    return pfn ? pfn * page_size + va % page_size : 0;
}

/* 驗證頁面起點對齊，以及指定的每一個 byte 都有正確的頁內偏移。 */
static enum test_result check_offsets(uintptr_t va, size_t size, size_t page_size,
                                      int pagemap)
{
    const size_t offsets[] = { 123, size - 1, page_size + 123 };
    uint64_t base = get_pa(va);
    bool passed = base != 0 && base % size == 0;

    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
        size_t offset = offsets[i];
        uint64_t before, actual, after;

        if (offset >= size)
            continue;
        before = pagemap_pa(pagemap, va + offset, page_size);
        actual = get_pa(va + offset);
        after = pagemap_pa(pagemap, va + offset, page_size);
        if (actual != base + offset) {
            printf("  Offset %zu: got 0x%" PRIx64 ", expected 0x%" PRIx64 "\n",
                   offset, actual, base + offset);
            passed = false;
        }
        if (before && before == after && actual != before) {
            printf("  Offset %zu: syscall PA 0x%" PRIx64 ", pagemap PA 0x%" PRIx64 "\n",
                   offset, actual, before);
            passed = false;
        }
    }
    printf("  Mapping base PA = 0x%" PRIx64 "\n", base);
    if (get_pa(va) != base)
        return TEST_SKIP;
    return passed ? TEST_PASS : TEST_FAIL;
}

static void test_regular_page(struct summary *summary, size_t page_size,
                              int pagemap, bool interrupt_injection)
{
    size_t region_size = 3 * page_size;
    void *region = mmap(NULL, region_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *page;
    uintptr_t va;
    uint64_t before, actual, after;
    enum test_result offsets;

    if (region == MAP_FAILED) {
        report(summary, TEST_FAIL, "Allocate a regular page", strerror(errno));
        return;
    }
    /* 兩側都保留不可存取的頁面，讓可寫的區域只有一個 4 KiB 頁面。 */
    page = (unsigned char *)region + page_size;
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE) == -1) {
        report(summary, TEST_FAIL, "Prepare a regular page", strerror(errno));
        munmap(region, region_size);
        return;
    }
    va = (uintptr_t)page;
    expect_zero(summary, "New anonymous page before first access", va);
    *(volatile unsigned char *)page = 0x5a;

    offsets = check_offsets(va, page_size, page_size, -1);
    report(summary, offsets, "4 KiB mapping and byte offsets",
           offsets == TEST_SKIP ? "PA changed during the checks" : NULL);

    before = pagemap_pa(pagemap, va + 123, page_size);
    actual = get_pa(va + 123);
    after = pagemap_pa(pagemap, va + 123, page_size);
    if (!before || before != after) {
        report(summary, TEST_SKIP, "Exact PA compared with /proc/self/pagemap",
               "PFN unavailable or changed during the check");
    } else {
        printf("  syscall PA = 0x%" PRIx64 ", pagemap PA = 0x%" PRIx64 "\n",
               actual, before);
        report(summary, actual == before ? TEST_PASS : TEST_FAIL,
               "Exact PA compared with /proc/self/pagemap", NULL);
    }

    if (interrupt_injection && offsets == TEST_PASS) {
        expect_zero(summary, "Simulated interrupted lookup (-EINTR)", va + INTERRUPT_OFFSET);
    } else {
        report(summary, TEST_SKIP, "Simulated interrupted lookup (-EINTR)",
               interrupt_injection ? "regular page control did not pass" : "use --interrupt-injection with the test kernel");
    }

    if (munmap(region, region_size) == -1) {
        report(summary, TEST_FAIL, "Unmap the regular page", strerror(errno));
        return;
    }
    expect_zero(summary, "Same address after munmap", va);
}

/* Linux 5.15 在 smaps 的 AnonHugePages 欄位列出由 PMD 映射的匿名大頁面。 */
static bool is_pmd_thp(uintptr_t va)
{
    FILE *smaps = fopen("/proc/self/smaps", "r");
    char line[512];
    bool in_mapping = false;
    bool confirmed = false;

    if (!smaps)
        return false;
    while (fgets(line, sizeof(line), smaps)) {
        uintptr_t start, end;
        unsigned long huge_kib;

        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) == 2) {
            if (in_mapping)
                break;
            in_mapping = start == va && end == va + pmd_size;
        } else if (in_mapping && sscanf(line, "AnonHugePages: %lu kB", &huge_kib) == 1) {
            confirmed = huge_kib == pmd_size / 1024;
            break;
        }
    }
    fclose(smaps);
    return confirmed;
}

static void test_pmd(struct summary *summary, size_t page_size, int pagemap)
{
    const char *name = "2 MiB transparent huge page (PMD)";
    void *region = mmap(NULL, 2 * pmd_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uintptr_t va;
    enum test_result result = TEST_SKIP;
    const char *detail = "smaps did not confirm a stable 2 MiB THP";

    if (region == MAP_FAILED) {
        report(summary, TEST_SKIP, name, strerror(errno));
        return;
    }
    va = ((uintptr_t)region + pmd_size - 1) & ~(uintptr_t)(pmd_size - 1);
    if (mprotect((void *)va, pmd_size, PROT_READ | PROT_WRITE) == -1 ||
        madvise((void *)va, pmd_size, MADV_HUGEPAGE) == -1) {
        detail = "could not set up an aligned THP mapping";
    } else {
        *(volatile unsigned char *)va = 0x5a;
        if (is_pmd_thp(va)) {
            result = check_offsets(va, pmd_size, page_size, pagemap);
            if (!is_pmd_thp(va))
                result = TEST_SKIP;
        }
    }
    munmap(region, 2 * pmd_size);
    report(summary, result, name, result == TEST_SKIP ? detail : NULL);
}

/* 在子程序測 HugeTLB，避免 1 GiB 頁面配置失敗時的 SIGBUS 終止其他測項。 */
static enum test_result check_pud_mapping(size_t page_size)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (30 << MAP_HUGE_SHIFT);
    void *page = mmap(NULL, pud_size, PROT_READ | PROT_WRITE, flags, -1, 0);
    enum test_result result;
    int pagemap;

    if (page == MAP_FAILED) {
        printf("  mmap (1 GiB HugeTLB): %s\n", strerror(errno));
        return TEST_SKIP;
    }
    *(volatile unsigned char *)page = 0x5a;
    pagemap = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    result = check_offsets((uintptr_t)page, pud_size, page_size, pagemap);
    if (pagemap >= 0)
        close(pagemap);
    munmap(page, pud_size);
    return result;
}

static void test_pud(struct summary *summary, size_t page_size, bool enabled)
{
    const char *name = "1 GiB HugeTLB page (PUD)";
    pid_t child, waited;
    int status;

    if (!enabled) {
        report(summary, TEST_SKIP, name, "use --hugetlb-1g when a 1 GiB page is reserved");
        return;
    }
    fflush(stdout);
    child = fork();
    if (child < 0) {
        report(summary, TEST_FAIL, name, strerror(errno));
        return;
    }
    if (child == 0) {
        enum test_result result = check_pud_mapping(page_size);

        fflush(stdout);
        _exit(result);
    }
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        report(summary, TEST_FAIL, name, strerror(errno));
    } else if (WIFEXITED(status)) {
        report(summary, WEXITSTATUS(status), name, NULL);
    } else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS) {
        report(summary, TEST_SKIP, name, "could not fault in a 1 GiB page");
    } else {
        report(summary, TEST_FAIL, name, "test subprocess terminated unexpectedly");
    }
}

/* 只接受 /proc/iomem 有列出、且沒有落入 System RAM 的實體位址。 */
static bool is_known_non_ram(uint64_t pa)
{
    FILE *iomem = fopen("/proc/iomem", "r");
    char line[512];
    bool known = false;

    if (!iomem)
        return false;
    while (fgets(line, sizeof(line), iomem)) {
        uint64_t start, end;
        char name[128];

        if (sscanf(line, " %" SCNx64 "-%" SCNx64 " : %127[^\n]", &start, &end, name) != 3 ||
            pa < start || pa > end)
            continue;
        if (strcmp(name, "System RAM") == 0) {
            fclose(iomem);
            return false;
        }
        known = true;
    }
    fclose(iomem);
    return known;
}

static void test_mmio(struct summary *summary, size_t page_size, int pagemap,
                      const char *path, off_t offset)
{
    const char *name = "Present non-RAM mapping returns 0";
    int fd;
    void *page;
    uint64_t pa;

    if (!path) {
        report(summary, TEST_SKIP, name, "use --mmio DEVICE OFFSET with a known MMIO mapping");
        return;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        report(summary, TEST_SKIP, name, strerror(errno));
        return;
    }
    page = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, offset);
    if (page == MAP_FAILED) {
        report(summary, TEST_SKIP, name, strerror(errno));
        close(fd);
        return;
    }
    close(fd);

    /* 不讀寫裝置。只有驅動已建立映射，且能獨立確認它不在 RAM 時才執行。 */
    pa = pagemap_pa(pagemap, (uintptr_t)page, page_size);
    if (pa && is_known_non_ram(pa))
        expect_zero(summary, name, (uintptr_t)page);
    else
        report(summary, TEST_SKIP, name, "pagemap and iomem could not confirm a present non-RAM page");
    munmap(page, page_size);
}

int main(int argc, char **argv)
{
    struct summary summary = {0};
    bool hugetlb_1g = false;
    bool interrupt_injection = false;
    const char *mmio_path = NULL;
    off_t mmio_offset = 0;
    long page_size = sysconf(_SC_PAGESIZE);
    int pagemap;

    if (page_size != 4096 || sizeof(uintptr_t) != 8) {
        fputs("This test targets x86-64 Linux with 4 KiB base pages.\n", stderr);
        return EXIT_FAILURE;
    }
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--hugetlb-1g") == 0) {
            hugetlb_1g = true;
        } else if (strcmp(argv[i], "--interrupt-injection") == 0) {
            interrupt_injection = true;
        } else if (strcmp(argv[i], "--mmio") == 0 && i + 2 < argc) {
            char *end;
            uint64_t offset;

            mmio_path = argv[++i];
            errno = 0;
            offset = strtoull(argv[++i], &end, 0);
            if (errno || end == argv[i] || *end || offset > INT64_MAX || offset % page_size) {
                fputs("MMIO offset must be a non-negative, page-aligned byte offset.\n", stderr);
                return EXIT_FAILURE;
            }
            mmio_offset = (off_t)offset;
        } else {
            fprintf(stderr, "Usage: %s [--hugetlb-1g] [--interrupt-injection] [--mmio DEVICE OFFSET]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    pagemap = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    test_regular_page(&summary, page_size, pagemap, interrupt_injection);
    expect_zero(&summary, "NULL address", 0);
    expect_zero(&summary, "Kernel-space address", (uintptr_t)UINT64_C(0xffff888000001000));
    test_pmd(&summary, page_size, pagemap);
    test_pud(&summary, page_size, hugetlb_1g);
    test_mmio(&summary, page_size, pagemap, mmio_path, mmio_offset);
    report(&summary, TEST_SKIP, "Real signal interrupts a blocked lookup", "requires a kernel trace of the interrupted lock and syscall return");
    if (pagemap >= 0)
        close(pagemap);

    printf("Summary: %u passed, %u failed, %u skipped\n",
           summary.passed, summary.failed, summary.skipped);
    return summary.failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
