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
 * This header file contains the definitions of the P+P data structure and
 * some useful functions related to it.
 */
 

#ifndef HEADER_CACHE_CONF_H
#define HEADER_CACHE_CONF_H

#include <assert.h>
#include <stdlib.h>

#include "device_conf.h"

#define PLRU_REPS 8

#define SET_MASK(SETS) (((((uintptr_t) SETS) * CACHELINE_SIZE) - 1) ^ (CACHELINE_SIZE - 1))

#define PAGE_MASK (PAGE_SIZE - 1)
#define REMOVE_PAGE_OFFSET(ptr) ((void *) (((uintptr_t) ptr) & ~PAGE_MASK))
#define GET_BIT(b, i) (((b & (1 << i)) >> i) & 1)
#define SET_BIT(b, i) (b | (1 << i))

/* Operate cacheline flags
 * Used flags:
 *  32                    2              1       0
 * |  | ... | cache group initialized | last | first |
 */
#define DEFAULT_FLAGS 0
#define SET_FIRST(flags) SET_BIT(flags, 0)
#define SET_LAST(flags) SET_BIT(flags, 1)
#define SET_CACHE_GROUP_INIT(flags) SET_BIT(flags, 2)
#define IS_FIRST(flags) GET_BIT(flags, 0)
#define IS_LAST(flags) GET_BIT(flags, 1)
#define IS_CACHE_GROUP_INIT(flags) GET_BIT(flags, 2)

// Offset of the next and prev field in the cacheline struct
#define CL_NEXT_OFFSET 0
#define CL_PREV_OFFSET 8

typedef enum cache_level cache_level;
typedef enum addressing_type addressing_type;
typedef struct cacheline cacheline;
typedef struct cache_ctx cache_ctx;
typedef uint32_t time_type;

enum cache_level {L1, L2};
enum addressing_type {VIRTUAL, PHYSICAL};

struct cache_ctx {
    cache_level cache_level;
    addressing_type addressing;

    uint32_t sets;
    uint32_t associativity;
    uint32_t access_time;
    uint32_t nr_of_cachelines;
    uint32_t set_size;
    uint32_t cache_size;
};

struct cacheline {
    // Doubly linked list inside same set
    // Attention: CL_NEXT_OFFSET and CL_PREV_OFFSET
    // must be kept up to date
    cacheline *next;
    cacheline *prev;

    uint16_t cache_set;
    uint16_t flags;
    time_type time_msrmt;

    // Unused padding to fill cache line
    char padding[CACHELINE_SIZE - 2 * sizeof(cacheline *)
                    - 2 * sizeof(uint16_t) - sizeof(time_type)];
};

/*
 * Initialises the context for the given cache level.
 * Returns null for unsupported or unknown cache level.
 */
static cache_ctx *get_cache_ctx(cache_level cache_level) {
    cache_ctx *ctx = (cache_ctx *) malloc(sizeof(cache_ctx));
    assert(ctx);

    if (cache_level == L1) {
        ctx->addressing     = L1_ADDRESSING;
        ctx->sets           = L1_SETS;
        ctx->associativity  = L1_ASSOCIATIVITY;
        ctx->access_time    = L1_ACCESS_TIME;
    }
    else if (cache_level == L2) {
        ctx->addressing     = L2_ADDRESSING;
        ctx->sets           = L2_SETS;
        ctx->associativity  = L2_ASSOCIATIVITY;
        ctx->access_time    = L2_ACCESS_TIME;
    }
    else {
        return NULL;
    }

    ctx->cache_level        = cache_level;
    ctx->nr_of_cachelines   = ctx->sets * ctx->associativity;
    ctx->set_size           = CACHELINE_SIZE * ctx->associativity;
    ctx->cache_size         = ctx->sets * ctx->set_size;

    return ctx;
}

static void release_cache_ctx(cache_ctx *ctx) {
    free(ctx);
}

/*
 * Removes bits that define the cache set from a pointer
 */
static void *remove_cache_set(cache_ctx *ctx, void *ptr) {
    return (void *) (((uintptr_t) ptr) & ~SET_MASK(ctx->sets));
}

/*
 * Removes bits that define the cache set from a pointer
 */
static void *remove_cache_group_set(void *ptr) {
    return (void *) (((uintptr_t) ptr) & ~SET_MASK(CACHE_GROUP_SIZE));
}

/*
 * Replace a cachline entry in the cache ds with another cacheline
 */
static void cl_replace(cacheline *new_cl, cacheline *old_cl) {
    old_cl->next->prev = new_cl;
    old_cl->prev->next = new_cl;

    new_cl->next = old_cl->next;
    new_cl->prev = old_cl->prev;
}

/*
 * Insert a cachline entry in the cache ds after the given cl
 */
static void cl_insert(cacheline *last_cl, cacheline *new_cl) {
    if (last_cl == NULL) {
        // Adding the first entry is a special case
        new_cl->next = new_cl;
        new_cl->prev = new_cl;
    }
    else {
        new_cl->next        = last_cl->next;
        new_cl->prev        = last_cl;
        last_cl->next->prev = new_cl;
        last_cl->next       = new_cl;
    }
}

/*
 * Remove a cachline entry from the cache ds
 */
static void cl_remove(cacheline *cl) {
    if (cl->prev != NULL) {
        cl->prev->next = cl->next;
    }

    if (cl->next != NULL) {
        cl->next->prev = cl->prev;
    }
}

/*
 * Get the length of a cache datastructure (in # cachelines)
 */
static uint32_t get_cache_ds_len(cacheline *cache_ds) {
    uint32_t cnt        = 0;
    cacheline *curr_cl  = cache_ds;

    do {
        if (!curr_cl) {
            break;
        }
        ++cnt;
        curr_cl = curr_cl->prev;
    } while (curr_cl != cache_ds);

    return cnt;
}

/*
 * Check if privileges are sufficient to perform virtial to physical address
 * translation.
 */
static bool can_trans_phys_addrs(cache_ctx *ctx) {
    uintptr_t paddr = 0;
    return !get_phys_addr(&paddr, (uintptr_t) &paddr);
}

/*
 * Parse pointer to mask out the cache set to which it maps
 */
static uint16_t get_cache_set_helper(uint32_t sets, void *ptr) {
    return (uint16_t) ((((uintptr_t) ptr) & SET_MASK(sets)) / CACHELINE_SIZE);
}

/*
 * Get cache set to which the pointer maps with virtual addressing
 */
static uint16_t get_virt_cache_set(cache_ctx *ctx, void *ptr) {
    return get_cache_set_helper(ctx->sets, ptr);
}

/*
 * Get cache set to which the pointer maps with physical addressing
 */
static uint16_t get_phys_cache_set(cache_ctx *ctx, void *ptr) {
    uintptr_t paddr;

    assert(!get_phys_addr(&paddr, (uintptr_t) ptr));

    if (paddr == 0) {
        printf("Virtual to physical address translation failed, might be "
               "due to insufficient privileges.");
        assert(0);
    }

    return get_cache_set_helper(ctx->sets, (void *) paddr);
}

/*
 * Get the cache set to which a pointer maps, taking virtual/physical addressing
 * into account.
 */
static uint16_t get_cache_set(cache_ctx *ctx, void *ptr) {
    if (ctx->addressing == VIRTUAL) {
        return get_virt_cache_set(ctx, ptr);
    }
    else {
        return get_phys_cache_set(ctx, ptr);
    }
}

/*
 * Returns the ceiled number of cache lines that are used by a chunk
 * of memory of the given size.
 */
static uint32_t get_spanned_cache_lines(cache_ctx *ctx, uint64_t size) {
    uint32_t spanned_cache_lines = (size + CACHELINE_SIZE - 1) / CACHELINE_SIZE;

    if (spanned_cache_lines > ctx->nr_of_cachelines)
        return ctx->nr_of_cachelines;
    else
        return spanned_cache_lines;
}

/*
 * Fancy print the P+P cache line
 */
static void print_cacheline(cacheline *cl) {
    printf("cacheline = {\n\tnext: %p,\n\tprev: %p,\n\tcache set: %d,\n\t"
           "time_msrmt: %u,\n\tflags: %x\n}\n",
           cl->next, cl->prev, cl->cache_set, cl->time_msrmt, cl->flags
    );
}

/*
 * Fancy print cache context
 */
static void print_cache_ctx(cache_ctx *ctx) {
    printf("cache_ctx = {\n\tcache_level: %d,\n\tsets: %u,\n\tassociativity: %u,\n"
           "\taccess_time %u,\n\tnr_of_cachelines: %u,\n\tset_size: %u,\n"
           "\tcache_size: %u\n}\n",
           ctx->cache_level, ctx->sets, ctx->associativity, ctx->access_time,
           ctx->nr_of_cachelines, ctx->set_size, ctx->cache_size
    );
}

#endif // HEADER_CACHE_CONF_H
