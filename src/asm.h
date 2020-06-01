/*
 * This file is part of the CacheSC library (https://github.com/Miro-H/CacheSC),
 * which implements Prime+Probe attacks on virtually and physically indexed
 * caches.
 *
 * Copyright (C) 2020  Miro Haller
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Contact: miro.haller@alumni.ethz.ch
 *
 * Short description of this file:
 * This exposes a simple API to low level assembly code
 */

#ifndef HEADER_ASM_H
#define HEADER_ASM_H

#include <stdint.h>

#define CPUID_AFFECTED_REGS "rax", "rbx", "rcx", "rdx"
#define RDTSC_AFFECTED_REGS "edx", "eax"
#define RDTSCP_AFFECTED_REGS RDTSC_AFFECTED_REGS, "ecx"
#define TRANSFER_REG "r8"


static inline void clflush(void *p) __attribute__((always_inline));
static inline void lfence() __attribute__((always_inline));
static inline void sfence() __attribute__((always_inline));
static inline void mfence() __attribute__((always_inline));
static inline void cpuid(void) __attribute__((always_inline));
static inline void prefetcht0(void *p) __attribute__((always_inline));
static inline void incq(void *p) __attribute__((always_inline));
static inline void readq(void *p) __attribute__((always_inline));
static inline void rdtsc(void) __attribute__((always_inline));
static inline uint32_t accesstime(void *p) __attribute__((always_inline));
static inline uint32_t accesstime_overhead() __attribute__((always_inline));
static inline void nop_slide() __attribute__((always_inline));

static inline void clflush(void *p) {
    asm volatile(
        "clflush (%0)\n\t"
        :: "r" (p)
    );
}

static inline void lfence() {
    asm volatile(
        "lfence\n\t"
        ::
    );
}

static inline void sfence() {
    asm volatile(
        "sfence\n\t"
        ::
    );
}

static inline void mfence() {
    asm volatile(
        "mfence\n\t"
        ::
    );
}

static inline void cpuid() {
    asm volatile(
        "mov $0x80000005, %%eax\n\t"
        "cpuid\n\t"
        ::: CPUID_AFFECTED_REGS
    );
}

static inline void prefetcht0(void *p) {
    asm volatile(
        "prefetcht0 (%0)\n\t"
        :: "r" (p)
    );
}

static inline void readq(void *p) {
    asm volatile (
        "movq (%0), %%r10\n\t"
        :: "r" (p)
        : "r10"
    );
}

static inline void incq(void *p) {
    asm volatile(
        "incq (%0)\n\t"
        :: "r" (p)
    );
}

static inline void rdtsc() {
    asm volatile(
        "rdtsc\n\t"
        ::: RDTSC_AFFECTED_REGS
    );
}

static inline void start_timer() {
    nop_slide();
    asm volatile(
        "cpuid\n\t"
        "rdtsc\n\t"
        "mov %%eax, %%r8d\n\t"
        ::: CPUID_AFFECTED_REGS, TRANSFER_REG
    );
}

static inline void stop_timer(uint32_t *tsc_low) {
    asm volatile(
        "rdtscp\n\t"
        "mov %%eax, %%r9d\n\t"
        "cpuid\n\t"
        "sub %%r8d, %%r9d\n\t"
        "mov %%r9d, %0\n\t"
        : "=r" (*tsc_low)
        :: CPUID_AFFECTED_REGS, TRANSFER_REG, "r9"
    );
}

/*
 * Measuring time according to Intel's "How to Benchmark
 * Code Execution Times" guide.
 */
static inline uint32_t accesstime(void *p) {
    uint32_t tsc_low = 0;

    asm volatile (
        "cpuid\n\t"
        "rdtsc\n\t"
        "mov %%eax, %%r8d\n\t"
        //"movq (%1), %%r10\n\t"
        "incq (%1)\n\t"
        "rdtscp\n\t"
        "mov %%eax, %%r9d\n\t"
        "cpuid\n\t"
        "decq (%1)\n\t"
        "sub %%r8d, %%r9d\n\t"
        "mov %%r9d, %0\n\t"
        : "=r" (tsc_low)
        : "r" (p)
        : CPUID_AFFECTED_REGS, "r8", "r9"//, "r10"
    );

    return tsc_low;
}

static inline uint32_t accesstime_overhead() {
    uint32_t tsc_low = 0;

    nop_slide();
    start_timer();
    stop_timer(&tsc_low);

    return tsc_low;
}

// Ivy Bridge has a 14-19 stage pipeline
static inline void nop_slide() {
    asm volatile (
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
    );
}

#endif // HEADER_ASM_H
