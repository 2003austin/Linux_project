#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_MY_GET_PHYSICAL_ADDRESSES
#define SYS_MY_GET_PHYSICAL_ADDRESSES 449
#endif
#define HUGE_SIZE (2UL * 1024 * 1024)

static char *region;
static size_t page_size;
static atomic_int running = 1;
static atomic_ulong queries, zeros, errors, toggles;

static void *query_worker(void *arg)
{
    (void)arg;
    /* Query addresses in the same hugepage while another thread splits its PMD. */
    unsigned long i = 0;
    while (atomic_load_explicit(&running, memory_order_relaxed)) {
        char *addr = region + ((i++ * page_size) % HUGE_SIZE);
        errno = 0;
        long ret = syscall(SYS_MY_GET_PHYSICAL_ADDRESSES, addr);
        if (ret == -1 && errno != 0)
            atomic_fetch_add(&errors, 1);
        else if (ret == 0)
            atomic_fetch_add(&zeros, 1);
        atomic_fetch_add(&queries, 1);
    }
    return NULL;
}

static void *split_worker(void *arg)
{
    (void)arg;
    char *target = region + page_size;
    while (atomic_load_explicit(&running, memory_order_relaxed)) {
        /* A subrange protection change can split a huge PMD into PTE mappings. */
        if (mprotect(target, page_size, PROT_READ) != 0) {
            perror("mprotect(PROT_READ)");
            atomic_store(&running, 0);
            break;
        }
        if (mprotect(target, page_size, PROT_READ | PROT_WRITE) != 0) {
            perror("mprotect(PROT_READ|PROT_WRITE)");
            atomic_store(&running, 0);
            break;
        }
        atomic_fetch_add(&toggles, 1);
    }
    return NULL;
}

static void print_anon_hugepages(void)
{
    FILE *f = fopen("/proc/self/smaps", "r");
    if (!f) { perror("smaps"); return; }
    char *line = NULL;
    size_t cap = 0;
    uintptr_t start = (uintptr_t)region;
    int in_region = 0;
    unsigned long total_kb = 0;
    while (getline(&line, &cap, f) != -1) {
        unsigned long lo, hi;
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2) {
            in_region = (lo <= start && start < hi);
        } else if (in_region && sscanf(line, "AnonHugePages: %lu kB", &lo) == 1) {
            total_kb += lo;
        }
    }
    printf("AnonHugePages for mapping containing base: %lu kB\n", total_kb);
    free(line);
    fclose(f);
}

int main(int argc, char **argv)
{
    int seconds = 10;
    if (argc > 1) {
        seconds = atoi(argv[1]);
        if (seconds < 1 || seconds > 300) {
            fprintf(stderr, "Usage: %s [seconds: 1..300]\n", argv[0]);
            return 2;
        }
    }
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0 || HUGE_SIZE % page_size) {
        fprintf(stderr, "Unsupported page size\n");
        return 2;
    }
    /* Overallocate and trim to guarantee a 2 MiB aligned VMA. */
    void *raw = mmap(NULL, HUGE_SIZE * 2, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) { perror("mmap"); return 1; }
    uintptr_t begin = (uintptr_t)raw;
    uintptr_t aligned = (begin + HUGE_SIZE - 1) & ~(HUGE_SIZE - 1);
    size_t prefix = aligned - begin;
    size_t suffix = HUGE_SIZE - prefix;
    if (prefix && munmap(raw, prefix)) { perror("munmap prefix"); return 1; }
    if (suffix && munmap((void *)(aligned + HUGE_SIZE), suffix)) {
        perror("munmap suffix"); return 1;
    }
    region = (char *)aligned;
    if (madvise(region, HUGE_SIZE, MADV_HUGEPAGE)) {
        perror("madvise(MADV_HUGEPAGE)"); return 1;
    }
    for (size_t i = 0; i < HUGE_SIZE; i += page_size)
        region[i] = (char)(i / page_size);

    printf("Region=%p, length=%lu, page_size=%zu, syscall=%d\n",
           (void *)region, (unsigned long)HUGE_SIZE, page_size,
           SYS_MY_GET_PHYSICAL_ADDRESSES);
    print_anon_hugepages();
    puts("NOTE: AnonHugePages=0 means THP was not confirmed; this run may only test PTE paths.");
    puts("NOTE: Repeated mprotect toggles do NOT guarantee repeated hugepage splits.");
    pthread_t query_thread, split_thread;
    if (pthread_create(&query_thread, NULL, query_worker, NULL)) {
        fprintf(stderr, "pthread_create query failed\n"); return 1;
    }
    if (pthread_create(&split_thread, NULL, split_worker, NULL)) {
        fprintf(stderr, "pthread_create split failed\n");
        atomic_store(&running, 0);
        pthread_join(query_thread, NULL);
        return 1;
    }
    sleep((unsigned int)seconds);
    atomic_store(&running, 0);
    pthread_join(query_thread, NULL);
    pthread_join(split_thread, NULL);
    printf("queries=%lu, zero_results=%lu, syscall_errors=%lu, mprotect_cycles=%lu\n",
           atomic_load(&queries), atomic_load(&zeros), atomic_load(&errors),
           atomic_load(&toggles));
    print_anon_hugepages();
    if (munmap(region, HUGE_SIZE)) perror("munmap");
    puts("Check dmesg for kernel warnings/oops; no crash is not proof of race freedom.");
    return 0;
}
