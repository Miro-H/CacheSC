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
 * This file contains a collection of "victims" that implement basic cache
 * eviction scenarios of possible victim processes.
 */

#ifndef HEADER_VICTIM_H
#define HEADER_VICTIM_H

#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "asm.h"
#include "cache.h"

cacheline *prepare_victim(cache_ctx *ctx, uint32_t target_set);
void release_victim(cache_ctx *ctx, cacheline *victim);

__attribute__((always_inline))
static inline void victim(void *p);
__attribute__((always_inline))
static inline void victim_clflush(void *p);
__attribute__((always_inline))
static inline void victim_loop(void *p, uint32_t nr);
__attribute__((always_inline))
static inline void victim_access_until_cached(cache_ctx *ctx, void *p);
__attribute__((always_inline))


/*
 * Basic victim: makes a single pointer access, protected against previous
 * memory accesses.
 */
static inline void victim(void *p) {
    mfence();
    readq(p);
}

/*
 * Explicitly flush a pointer from all cache levels.
 */
static inline void victim_clflush(void *p) {
    clflush(p);
}

/*
 * Repeatedly access the same pointer to increase the chance that it is cached
 * in case some sophisticated priorisation is performed.
 */
static inline void victim_loop(void *p, uint32_t nr) {
    for (uint32_t i = 0; i < nr; ++i) {
        victim(p);
    }
}

/*
 * Access a pointer until the measured access time corresponds to the
 * expected latency of the given cache level.
 */
static inline void victim_access_until_cached(cache_ctx *ctx, void *p) {
    while(!is_cached(ctx, p));
}

#endif // HEADER_VICTIM_H
