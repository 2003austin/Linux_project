#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

/* Change these only after confirming your group's running kernel and syscall table. */
#ifndef PROJECT_KERNEL_RELEASE
#define PROJECT_KERNEL_RELEASE "5.15.135-syscall449-liu-update3"
#endif
#ifndef PROJECT_SYSCALL_NR
#define PROJECT_SYSCALL_NR 449
#endif

static int failures;

static uintptr_t physical_address(uintptr_t virtual_address)
{
    errno = 0;
    long result = syscall(PROJECT_SYSCALL_NR, (void *)virtual_address);
    if (result == -1 && errno != 0) {
        perror("project syscall");
        exit(EXIT_FAILURE);
    }
    return (uintptr_t)result;
}

static void check(const char *name, int ok, uintptr_t actual, uintptr_t expected)
{
    printf("[%s] %s (actual=%#" PRIxPTR ", expected=%#" PRIxPTR ")\n",
           ok ? "PASS" : "FAIL", name, actual, expected);
    failures += !ok;
}

static void check_file_mapping(size_t page)
{
    FILE *file = tmpfile();
    if (file == NULL || fputc('F', file) == EOF || fflush(file) == EOF ||
        ftruncate(fileno(file), (off_t)page) == -1) {
        perror("prepare temporary file");
        exit(EXIT_FAILURE);
    }

    volatile unsigned char *first = mmap(NULL, page, PROT_READ, MAP_PRIVATE, fileno(file), 0);
    volatile unsigned char *second = mmap(NULL, page, PROT_READ, MAP_PRIVATE, fileno(file), 0);
    if (first == MAP_FAILED || second == MAP_FAILED) {
        perror("mmap file");
        exit(EXIT_FAILURE);
    }

    puts("\nFile-backed pages: same file offset, two virtual mappings");
    uintptr_t before_first = physical_address((uintptr_t)first);
    uintptr_t before_second = physical_address((uintptr_t)second);
    check("first file VA has no present mapping before access", before_first == 0, before_first, 0);
    check("second file VA has no present mapping before access", before_second == 0, before_second, 0);

    unsigned char first_value = first[0];
    unsigned char second_value = second[0];
    uintptr_t first_pa = physical_address((uintptr_t)first);
    uintptr_t second_pa = physical_address((uintptr_t)second);
    check("first mapping reads the file byte", first_value == 'F', first_value, 'F');
    check("second mapping reads the file byte", second_value == 'F', second_value, 'F');
    check("both file VAs map to the same present frame",
          first_pa != 0 && first_pa == second_pa, second_pa, first_pa);

    if (munmap((void *)first, page) == -1 || munmap((void *)second, page) == -1) {
        perror("munmap file");
        exit(EXIT_FAILURE);
    }
    fclose(file);
}

static size_t pmd_page_size(void)
{
    FILE *file = fopen("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", "r");
    if (file == NULL)
        return 0;

    size_t size = 0;
    if (fscanf(file, "%zu", &size) != 1)
        size = 0;
    fclose(file);
    return size;
}

static int mapping_has_thp(uintptr_t address, size_t size)
{
    FILE *file = fopen("/proc/self/smaps", "r");
    if (file == NULL)
        return 0;

    char line[512];
    int selected = 0;
    int found = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        uintptr_t start, end;
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) == 2) {
            if (selected)
                break;
            selected = start == address && end - start == size;
        }
        size_t kib;
        if (selected && sscanf(line, "AnonHugePages: %zu kB", &kib) == 1) {
            found = kib >= size / 1024;
            break;
        }
    }
    fclose(file);
    return found;
}

static void check_thp(size_t page)
{
    size_t huge = pmd_page_size();
    if (huge <= page || huge > SIZE_MAX / 2 || (huge & (huge - 1)) != 0) {
        puts("[SKIP] No usable PMD-sized transparent huge page setting.");
        return;
    }

    void *reservation = mmap(NULL, huge * 2, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED) {
        perror("reserve THP address range");
        exit(EXIT_FAILURE);
    }
    uintptr_t address = ((uintptr_t)reservation + huge - 1) & ~(uintptr_t)(huge - 1);
    volatile unsigned char *region =
        mmap((void *)address, huge, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (region == MAP_FAILED) {
        perror("map aligned THP region");
        exit(EXIT_FAILURE);
    }

    if (madvise((void *)region, huge, MADV_HUGEPAGE) == -1) {
        puts("[SKIP] MADV_HUGEPAGE was not accepted.");
    } else {
        region[0] = 'H';
        region[page + 100] = 'M';
        region[huge - 1] = 'T';
        if (!mapping_has_thp(address, huge)) {
            puts("[SKIP] smaps did not confirm a PMD-sized anonymous THP.");
        } else {
            printf("\nTHP: smaps confirmed %zu bytes of anonymous huge-page backing\n", huge);
            uintptr_t start_pa = physical_address(address);
            uintptr_t middle_pa = physical_address(address + page + 100);
            uintptr_t end_pa = physical_address(address + huge - 1);
            check("THP start has a present mapping", start_pa != 0, start_pa != 0, 1);
            check("THP offset crosses the first base page",
                  start_pa != 0 && middle_pa == start_pa + page + 100,
                  middle_pa, start_pa + page + 100);
            check("THP final byte keeps its offset within the huge page",
                  start_pa != 0 && end_pa == start_pa + huge - 1,
                  end_pa, start_pa + huge - 1);
        }
    }

    if (munmap(reservation, huge * 2) == -1) {
        perror("unmap THP range");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--thp") != 0)) {
        fprintf(stderr, "Usage: %s [--thp]\n", argv[0]);
        return EXIT_FAILURE;
    }
    struct utsname kernel;
    if (uname(&kernel) == -1) {
        perror("uname");
        return EXIT_FAILURE;
    }
    if (strcmp(kernel.release, PROJECT_KERNEL_RELEASE) != 0) {
        fprintf(stderr, "[SKIP] Running kernel is %s. Expected %s.\n",
                kernel.release, PROJECT_KERNEL_RELEASE);
        return 77;
    }

    long size = sysconf(_SC_PAGESIZE);
    if (size <= 100) {
        fprintf(stderr, "Unexpected page size: %ld\n", size);
        return EXIT_FAILURE;
    }
    size_t page = (size_t)size;
    volatile unsigned char *region = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }
    uintptr_t start = (uintptr_t)region;
    uintptr_t next = start + page;

    puts("State 1: query before accessing the new anonymous mapping");
    uintptr_t untouched_first = physical_address(start);
    check("first page has no present mapping", untouched_first == 0, untouched_first, 0);
    uintptr_t untouched_second = physical_address(next);
    check("second page has no present mapping", untouched_second == 0, untouched_second, 0);

    puts("\nState 2: read both pages, then query");
    unsigned char first_value = region[0];
    unsigned char second_value = region[page];
    check("first page initially reads zero", first_value == 0, first_value, 0);
    check("second page initially reads zero", second_value == 0, second_value, 0);
    uintptr_t zero_first = physical_address(start);
    uintptr_t zero_second = physical_address(next);
    uintptr_t offset_pa = physical_address(start + 100);
    check("both reads map to the same present frame",
          zero_first != 0 && zero_first == zero_second, zero_second, zero_first);
    check("translation preserves the offset of byte 100",
          zero_first != 0 && offset_pa == zero_first + 100, offset_pa, zero_first + 100);

    puts("\nState 3: write only to the first page");
    region[0] = 'X';
    uintptr_t private_first = physical_address(start);
    uintptr_t private_offset = physical_address(start + 100);
    uintptr_t still_shared = physical_address(next);
    printf("[INFO] First page PA before/after write: %#" PRIxPTR " -> %#" PRIxPTR "\n",
           zero_first, private_first);
    int private_frame = private_first != 0 && zero_first != 0 && private_first != zero_first;
    check("first page uses a present private frame", private_frame, private_frame, 1);
    check("byte 100 follows the first page and keeps its offset",
          private_first != 0 && private_offset == private_first + 100,
          private_offset, private_first + 100);
    check("second page keeps its original mapping",
          zero_second != 0 && still_shared == zero_second, still_shared, zero_second);
    unsigned char written = region[0];
    unsigned char neighbor = region[100];
    check("first byte contains the written value", written == 'X', written, 'X');
    check("byte 100 still contains zero", neighbor == 0, neighbor, 0);

    puts("\nAfter unmap: query the old addresses without dereferencing them");
    if (munmap((void *)region, page * 2) == -1) {
        perror("munmap");
        return EXIT_FAILURE;
    }
    uintptr_t unmapped_first = physical_address(start);
    uintptr_t unmapped_second = physical_address(next);
    check("old first page has no present mapping", unmapped_first == 0, unmapped_first, 0);
    check("old second page has no present mapping", unmapped_second == 0, unmapped_second, 0);

    check_file_mapping(page);
    if (argc == 2)
        check_thp(page);
    printf("\nSummary: %d FAIL\n", failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
