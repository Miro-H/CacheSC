/*
 * Virtual to physical address translation based on the code of
 * https://github.com/cirosantilli/linux-kernel-module-cheat#userland-physical-address-experiments
 * visited on February 26, 2020.
 * Adapted to an API that translates the virtual addresses of the current
 * C file to physical addresses. Meta-comments are marked with []
 *
 * Split into header and implementation files.
 */

#ifndef ADDR_TRANSLATION_H
#define ADDR_TRANSLATION_H

// []: The relevant includes from the source and the unchanged data struct.
#define _XOPEN_SOURCE 700
#include <fcntl.h> /* open */
#include <stdint.h> /* uint64_t  */
#include <stdlib.h> /* size_t */
#include <stdio.h> /* snprintf */
#include <sys/types.h>
#include <unistd.h> /* pread, sysconf */

/* Format documented at:
 * https://github.com/torvalds/linux/blob/v4.9/Documentation/vm/pagemap.txt
 */
typedef struct {
    uint64_t pfn : 54;
    unsigned int soft_dirty : 1;
    unsigned int file_page : 1;
    unsigned int swapped : 1;
    unsigned int present : 1;
} PagemapEntry;

// []: Modified function
int get_phys_addr(uintptr_t *paddr, uintptr_t vaddr);

#endif // ADDR_TRANSLATION_H
