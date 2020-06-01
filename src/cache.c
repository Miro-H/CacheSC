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
 * This file contains functions to initialise the data structure for
 * Prime+Probe attacks. Functions that are time critical (such as prime and
 * probe) are as inlined static functions in the cache.h to avoid the overhead
 * of function calls.
 */

#include "cache.h"


// local functions
int cache_ds_sanity_check(cache_ctx *ctx, cacheline *head);
cacheline *build_cache_ds(cache_ctx *ctx, cacheline **cacheline_ptr_arr);
void build_randomized_list_for_cache_set(cache_ctx *ctx, cacheline **cacheline_ptr_arr);
cacheline **allocate_cache_ds(cache_ctx *ctx);
void allocate_cache_ds_phys(cache_ctx *ctx, cacheline **cl_ptr_arr);
void allocate_cache_ds_phys_unpriv(cache_ctx *ctx, cacheline **cl_ptr_arr,
    cacheline **cls_to_del);
void allocate_cache_ds_phys_priv(cache_ctx *ctx, cacheline **cl_ptr_arr,
    cacheline **cls_to_del);
uint32_t find_collisions(cache_ctx *ctx, cacheline *cl_candidates,
    cacheline **cache_set_ds_ptrs, uint32_t *cache_set_ds_lens);
void identify_cache_sets(cache_ctx *ctx, cacheline *coll_cl, cacheline *cache_set_ds,
    uint32_t cache_set_ds_len, uint32_t *cache_group);
bool has_collision(cache_ctx *ctx, cacheline *cl_candidate, cacheline *cache_set_ds,
    uint32_t cache_set_ds_len);
void finish_identifying_groups(cache_ctx *ctx, cacheline **cache_set_ds_ptrs,
    cacheline **cls_to_del, uint32_t *cache_group);


/*
 * Initialises the complete cache data structure for the given context
 */
cacheline *prepare_cache_ds(cache_ctx *ctx) {
    cacheline **cacheline_ptr_arr = allocate_cache_ds(ctx);

    cacheline *cache_ds = build_cache_ds(ctx, cacheline_ptr_arr);
    assert(!cache_ds_sanity_check(ctx, cache_ds));

    // release internal indirection data structure again
    free(cacheline_ptr_arr);

    return cache_ds;
}

/*
 * Initialises the cache data structure for the given context and set
 */
cacheline *prepare_cache_set_ds(cache_ctx *ctx, uint32_t *sets, uint32_t sets_len) {
    cacheline *cache_ds = prepare_cache_ds(ctx);

    cacheline **first_cl_in_sets = (cacheline **) calloc(ctx->sets,
                                                    sizeof(cacheline *));
    cacheline **last_cl_in_sets  = (cacheline **) calloc(ctx->sets,
                                                    sizeof(cacheline *));
    assert(first_cl_in_sets);
    assert(last_cl_in_sets);

    // Find the cache groups that are used, so that we can delete the other ones
    // later (to avoid memory leaks)
    uint32_t i, cache_groups_len;
    uint32_t cache_groups_max_len   = ctx->sets / CACHE_GROUP_SIZE;
    uint32_t *cache_groups          = (uint32_t *) malloc(cache_groups_max_len
                                                    * sizeof(uint32_t));
    assert(cache_groups);

    cache_groups_len = 0;
    for (i = 0; i < sets_len; ++i) {
        if (!is_in_arr(sets[i] / CACHE_GROUP_SIZE, cache_groups, cache_groups_len)) {
            cache_groups[cache_groups_len] = sets[i] / CACHE_GROUP_SIZE;
            ++cache_groups_len;
        }
    }

    cacheline *to_del_cls   = NULL;
    cacheline *curr_cl      = cache_ds;
    cacheline *next_cl, *cache_set_ds;

    // Extract the partial data structure for the cache sets and ensure correct freeing
    do {
        next_cl = curr_cl->next;

        if (IS_FIRST(curr_cl->flags)) {
            first_cl_in_sets[curr_cl->cache_set] = curr_cl;
        }
        if (IS_LAST(curr_cl->flags)) {
            last_cl_in_sets[curr_cl->cache_set] = curr_cl;
        }

        if (ctx->addressing == PHYSICAL && !is_in_arr(
            curr_cl->cache_set / CACHE_GROUP_SIZE, cache_groups, cache_groups_len))
        {
            // Already free all unused blocks of the cache ds for physical
            // addressing, because we loose their refs
            cl_insert(to_del_cls, curr_cl);
            to_del_cls = curr_cl;
        }
        curr_cl = next_cl;

    } while(curr_cl != cache_ds);

    // Fix partial cache set ds
    for (i = 0; i < sets_len; ++i) {
        last_cl_in_sets[sets[i]]->next = first_cl_in_sets[sets[(i + 1) % sets_len]];
        first_cl_in_sets[sets[(i + 1) % sets_len]]->prev = last_cl_in_sets[sets[i]];
    }
    cache_set_ds = first_cl_in_sets[sets[0]];

    // Free unused cache lines
    if (ctx->addressing == PHYSICAL) {
        release_cache_ds(ctx, to_del_cls);
    }

    free(first_cl_in_sets);
    free(last_cl_in_sets);
    free(cache_groups);

    return cache_set_ds;
}

/*
 * Allocate a data structure that fills the complete cache, i.e. consisting
 * of `associativity` many cache lines for each cache set.
 */
cacheline **allocate_cache_ds(cache_ctx *ctx) {
    cacheline **cl_ptr_arr;

    cl_ptr_arr = (cacheline **) malloc(ctx->nr_of_cachelines * sizeof(cacheline *));
    assert(cl_ptr_arr);

    if (ctx->addressing == VIRTUAL) {
        // For virtual addressing, allocating a consecutive chunk of memory is enough
        cacheline *cl_arr = (cacheline *) aligned_alloc(PAGE_SIZE, ctx->cache_size);
        assert(cl_arr);

        for (uint32_t i = 0; i < ctx->nr_of_cachelines; ++i) {
            cl_ptr_arr[i]               = cl_arr + i;
            cl_ptr_arr[i]->cache_set    = get_virt_cache_set(ctx, cl_ptr_arr[i]);
        }
    }
    else if (ctx->addressing == PHYSICAL) {
        allocate_cache_ds_phys(ctx, cl_ptr_arr);
    }

    return cl_ptr_arr;
}

/*
 * allocate_cache_ds for physical addressing:
 * For physical addressing, we either need privileges to translate virtual
 * to physical addresses and find the cache set, or we need to do measurements
 * to ensure that the cache lines are uniformly distributed over the sets.
 */
void allocate_cache_ds_phys(cache_ctx *ctx, cacheline **cl_ptr_arr) {
    cacheline *cls_to_del = NULL;

    if (can_trans_phys_addrs(ctx)) {
        allocate_cache_ds_phys_priv(ctx, cl_ptr_arr, &cls_to_del);
    }
    else {
        allocate_cache_ds_phys_unpriv(ctx, cl_ptr_arr, &cls_to_del);
    }

    // Free the unused cls
    cacheline *cl_to_del = cls_to_del;
    cacheline *next_cl_to_del;

    while (cl_to_del != NULL) {
        next_cl_to_del = cl_to_del->prev;
        free(cl_to_del);
        cl_to_del = next_cl_to_del;
    }
}

/*
 * With privileges, collision detection can just count the lines per set
 */
void allocate_cache_ds_phys_priv(cache_ctx *ctx, cacheline **cl_ptr_arr,
    cacheline **cls_to_del)
{
    cacheline *cl_candidates;
    uint32_t i;
    uint32_t cl_ptr_idx         = 0;
    uint32_t *cnt_lines_per_set = (uint32_t *) calloc(ctx->sets, sizeof(uint32_t));
    assert(cnt_lines_per_set);

    while (cl_ptr_idx < ctx->nr_of_cachelines) {
        cl_candidates = (cacheline *) aligned_alloc(PAGE_SIZE, PAGE_SIZE);
        assert(cl_candidates);
        memset(cl_candidates, 0, PAGE_SIZE);

        if (cnt_lines_per_set[get_phys_cache_set(ctx, cl_candidates)]
            < ctx->associativity)
        {
            for (i = 0; i < CACHE_GROUP_SIZE; ++i) {
                cl_candidates[i].cache_set = get_phys_cache_set(ctx, cl_candidates + i);
                cl_ptr_arr[cl_ptr_idx]     = cl_candidates + i;
                cl_ptr_idx++;
                cnt_lines_per_set[cl_candidates[i].cache_set] += 1;
            }
        }
        else {
            cl_candidates->prev = *cls_to_del;
            *cls_to_del         = cl_candidates;
        }
    }
}

/*
 * Without privileges, we must detect collisions with prime and probe, since not
 * more than `associativity` many cache lines of the same cache set can be held in L2
 * simultaneously.
 */
void allocate_cache_ds_phys_unpriv(cache_ctx *ctx, cacheline **cl_ptr_arr,
    cacheline **cls_to_del)
{
    cacheline *cl_candidate, *cl_candidates;
    uint32_t cl_candidate_set, i;
    uint32_t collisions;

    uint32_t cache_group    = 0;
    uint32_t cl_ptr_idx     = 0;

    uint32_t repeated_collisions = 0;

    // Maintain a list for all cache lines that map to the same L1 set (for
    // collision detection)
    cacheline **cache_set_ds_ptrs;
    uint32_t *cache_set_ds_lens;

    cache_set_ds_ptrs   = (cacheline **) calloc(CACHE_GROUP_SIZE, sizeof(cacheline *));
    cache_set_ds_lens   = (uint32_t *) calloc(CACHE_GROUP_SIZE, sizeof(uint32_t));
    assert(cache_set_ds_ptrs);

    while (cl_ptr_idx < ctx->nr_of_cachelines) {
        // Allocate a page containing CACHE_GROUP_SIZE cachelines
        //
        // Sometimes, only pages at an even or odd address are allocated
        // (after dividing by the page offset). To avoid waiting until the entire
        // memory was filled, we just allocate more than needed. Since this is likely
        // to be consecutive, we break the allocation pattern.
        if (repeated_collisions >= 3) {
            cl_candidates = (cacheline *) aligned_alloc(PAGE_SIZE, 2 * PAGE_SIZE);
            repeated_collisions = 0;
        }
        else {
            cl_candidates = (cacheline *) aligned_alloc(PAGE_SIZE, PAGE_SIZE);
        }
        assert(cl_candidates);
        memset(cl_candidates, 0, PAGE_SIZE);

        collisions = find_collisions(ctx, cl_candidates, cache_set_ds_ptrs,
                                     cache_set_ds_lens);

        // Try to find collisions
        if (collisions == CACHE_GROUP_SIZE) {
            ++repeated_collisions;

            cl_candidate_set = cl_candidates->cache_set % CACHE_GROUP_SIZE;
            identify_cache_sets(ctx, cl_candidates,
                                cache_set_ds_ptrs[cl_candidate_set],
                                cache_set_ds_lens[cl_candidate_set], &cache_group);

            cl_candidates->prev = *cls_to_del;
            *cls_to_del         = cl_candidates;
        }
        else {
            repeated_collisions = 0;

            for (i = 0; i < CACHE_GROUP_SIZE; ++i) {
                // Add all cache lines in the block to the data structure
                cl_candidate        = cl_candidates + i;
                cl_candidate_set    = cl_candidate->cache_set % CACHE_GROUP_SIZE;

                cl_ptr_arr[cl_ptr_idx]  = cl_candidate;

                // Maintain temporary cache ds for collision detection with P+P
                if (!cache_set_ds_ptrs[cl_candidate_set]) {
                    cache_set_ds_ptrs[cl_candidate_set] = cl_candidate;
                }
                cl_insert(cache_set_ds_ptrs[cl_candidate_set]->prev, cl_candidate);

                cache_set_ds_lens[cl_candidate_set]++;
                cl_ptr_idx++;
            }
        }
    }

    finish_identifying_groups(ctx, cache_set_ds_ptrs, cls_to_del, &cache_group);
}

/*
 * Decide whether a given cacheline `cl_candidate` causes a collision (and thus
 * should not be added to the cache ds).
 */
uint32_t find_collisions(cache_ctx *ctx, cacheline *cl_candidates,
    cacheline **cache_set_ds_ptrs, uint32_t *cache_set_ds_lens)
{
    uint32_t i, collisions, cl_candidate_set;
    cacheline *cl_candidate;

    collisions = 0;

    for (i = 0; i < CACHE_GROUP_SIZE; ++i) {
        cl_candidate = cl_candidates + i;

        // The offset inside a page is correct, i.e. modulo CACHE_GROUP_SIZE the
        // cache set of the virtual address is correct so we preserve that.
        cl_candidate_set        = get_virt_cache_set(ctx, cl_candidate)
                                  % CACHE_GROUP_SIZE;
        cl_candidate->cache_set = cl_candidate_set;

        // While there are at most as many lines as ways,
        // there is trivially no collision
        if (cache_set_ds_lens[cl_candidate_set] > ctx->associativity
            && has_collision(ctx, cl_candidate, cache_set_ds_ptrs[cl_candidate_set],
                                cache_set_ds_lens[cl_candidate_set]))
        {
            ++collisions;
        }
    }

    return collisions;
}

/*
 * Use a given collision to identify the other cache lines in that set.
 */
void identify_cache_sets(cache_ctx *ctx, cacheline *coll_cl, cacheline *cache_set_ds,
    uint32_t cache_set_ds_len, uint32_t *cache_group)
{
    bool found_collision;
    cacheline *curr_cl, *head_cl;
    cacheline **identified_cls;
    uint32_t identified_cls_idx, i, j;

    identified_cls_idx = ctx->associativity + 1;
    identified_cls = (cacheline **) malloc(ctx->associativity * sizeof(cacheline *));
    assert(identified_cls);

    identified_cls_idx = 0;

    // To find cachelines that belong to the same set we temporarily
    // replace another cacheline A of the same virtual set with the
    // colliding cacheline B and then check if A causes a collision.
    curr_cl = cache_set_ds;
    head_cl = coll_cl;

    do {
        // Only look at cachelines that were not yet categorized.
        if (!IS_CACHE_GROUP_INIT(curr_cl->flags)) {
            cl_replace(coll_cl, curr_cl);
            found_collision = has_collision(ctx, curr_cl, head_cl,
                                cache_set_ds_len);
            cl_replace(curr_cl, coll_cl);

            if (found_collision) {
                if (identified_cls_idx < ctx->associativity) {
                    identified_cls[identified_cls_idx] = (cacheline *)
                        remove_cache_group_set(curr_cl);
                }
                ++identified_cls_idx;
            }
        }
        curr_cl = curr_cl->next;
        head_cl = cache_set_ds;
    } while (curr_cl != cache_set_ds);

    if (identified_cls_idx == ctx->associativity) {
        // Mark all cachelines in the page of the collision
        for (i = 0; i < identified_cls_idx; ++i) {
            for (j = 0; j < CACHE_GROUP_SIZE; ++j) {
                identified_cls[i][j].cache_set = *cache_group * CACHE_GROUP_SIZE
                    + get_virt_cache_set(ctx, identified_cls[i] + j) % CACHE_GROUP_SIZE;
                identified_cls[i][j].flags = SET_CACHE_GROUP_INIT(
                                                   identified_cls[i][j].flags);
            }
        }

        *cache_group += 1;
    }
}

/*
 * Use P+P to decide whether the given cacheline cl_candidate causes a collision.
 * Test for collisions starting from every cacheline in the cache ds (because
 * the time is different depending on where you start, probably due to buffer
 * side effects). We have cache_set_ds_len - associativity >= 1 collisions if
 * the candidate maps to the same L2 set as associativity sets in the current ds
 */
bool has_collision(cache_ctx *ctx, cacheline *cl_candidate, cacheline *cache_set_ds,
    uint32_t cache_set_ds_len)
{
    uint32_t i, baseline_time;

    uint32_t collisions_overall;
    uint32_t time[COLLISION_REP];
    cacheline *cl_head = cache_set_ds;

    collisions_overall = 0;

    do {
        // Baseline current datastructure time
        for (i = 0; i < COLLISION_REP; ++i) {
            readq(cl_candidate);
            prime_rev(cl_head);
            time[i] = probe_full_ds(cl_head);
        }
        baseline_time = get_min(time, COLLISION_REP);

        cl_replace(cl_candidate, cl_head);

        for (i = 0; i < COLLISION_REP; ++i) {
            prime_rev(cl_candidate);
            time[i] = probe_full_ds(cl_candidate);
        }

        if (get_avg(time, COLLISION_REP) >= baseline_time +
                L3_ACCESS_TIME - L2_ACCESS_TIME)
        {
            ++collisions_overall;
        }

        cl_replace(cl_head, cl_candidate);
        cl_head = cl_head->next;
    } while (cl_head != cache_set_ds);

    return collisions_overall >= cache_set_ds_len - ctx->associativity;
}

/*
 * Make sure the cache lines of all groups were identified
 */
void finish_identifying_groups(cache_ctx *ctx, cacheline **cache_set_ds_ptrs,
    cacheline **cls_to_del, uint32_t *cache_group)
{
    cacheline *cl_candidates;
    uint32_t cl_candidate_set;

    while (*cache_group < ctx->sets / CACHE_GROUP_SIZE) {
        cl_candidates = (cacheline *) aligned_alloc(PAGE_SIZE, PAGE_SIZE);
        assert(cl_candidates);
        memset(cl_candidates, 0, PAGE_SIZE);

        cl_candidate_set = get_virt_cache_set(ctx, cl_candidates) % CACHE_GROUP_SIZE;

        identify_cache_sets(ctx, cl_candidates,
                                cache_set_ds_ptrs[cl_candidate_set],
                                CACHE_GROUP_SIZE, cache_group);

        cl_candidates->prev = *cls_to_del;
        *cls_to_del         = cl_candidates;
    }
}

/*
 * Sanity check on the cache datastructure:
 * - Verify that all cache sets are present and filled with the right number of lines
 * returns 0 on success
 */
int cache_ds_sanity_check(cache_ctx *ctx, cacheline *head) {
    cacheline *curr_cl = head;
    // One entry per set, counting the lines in this set
    uint32_t *line_cnt_arr = (uint32_t *) calloc(ctx->sets, sizeof(uint32_t));
    assert(line_cnt_arr);

    do {
        curr_cl = curr_cl->next;
        line_cnt_arr[curr_cl->cache_set] += 1;
    } while(curr_cl != head);

    for(uint32_t i = 0; i < ctx->sets; ++i) {
        if (line_cnt_arr[i] != ctx->associativity)
            return 1;
    }

    free(line_cnt_arr);
    return 0;
}

void release_cache_ds(cache_ctx *ctx, cacheline *cache_ds) {
    if (!cache_ds) {
        return;
    }

    cacheline *next_cl, *curr_cl, *cl_base;
    uint32_t i, ptrs_to_free_idx;
    void **ptrs_to_free;
    bool add_ptr;

    if (ctx->addressing == VIRTUAL) {
        free(remove_cache_set(ctx, cache_ds));
    }
    else {
        curr_cl             = cache_ds;
        ptrs_to_free_idx    = 0;
        ptrs_to_free        = (void **) malloc(ctx->cache_size / PAGE_SIZE
                                                     * sizeof(void *));
        assert(ptrs_to_free);

        // Store which pointers have to be freed later (they cannot be freed on
        // the go, as later cachelines might still be in this memory (use after free)
        do {
            next_cl = curr_cl->next;
            cl_base = remove_cache_group_set(curr_cl);

            add_ptr = true;
            for (i = 0; i < ptrs_to_free_idx; ++i) {
                if (cl_base == ptrs_to_free[i]) {
                    add_ptr = false;
                    break;
                }
            }

            if (add_ptr) {
                ptrs_to_free[ptrs_to_free_idx] = cl_base;
                ++ptrs_to_free_idx;
            }
            curr_cl = next_cl;
        } while (next_cl != cache_ds);

        // Free all pointers
        for (i = 0; i < ptrs_to_free_idx; ++i) {
            free(ptrs_to_free[i]);
        }

        free(ptrs_to_free);
    }
}

void release_cache_set_ds(cache_ctx *ctx, cacheline *cache_set_ds) {
    if (ctx->addressing == VIRTUAL) {
        free(remove_cache_set(ctx, cache_set_ds));
    }
    else {
        release_cache_ds(ctx, cache_set_ds);
    }
}

/*
 * Create a randomized doubly linked list with the following structure:
 * set A <--> set B <--> ... <--> set X <--> set A
 * where each set is one of the cache sets, in a random order.
 * The sets are a doubly linked list of cachelines themselves:
 * set A:
 *  line[A + x0 * #sets] <--> line[A + x1 * #sets] <--> ...
 * where x0, x1, ..., xD is a random permutation of 1, 2, ..., D
 * and D = Associativity = | cache set |
 */
cacheline *build_cache_ds(cache_ctx *ctx, cacheline **cl_ptr_arr) {
    cacheline **cl_ptr_arr_sorted = (cacheline **) malloc(
                                        ctx->nr_of_cachelines * sizeof(cacheline *));
    uint32_t *idx_per_set = (uint32_t *) calloc(ctx->sets, sizeof(uint32_t));

    assert(cl_ptr_arr_sorted);
    assert(idx_per_set);

    uint32_t set_len = ctx->associativity;

    // Build ptr list sorted by sets
    uint32_t idx_curr_set, set_offset;
    for (uint32_t i = 0; i < ctx->nr_of_cachelines; ++i) {
        set_offset      = cl_ptr_arr[i]->cache_set * set_len;
        idx_curr_set    = idx_per_set[cl_ptr_arr[i]->cache_set];

        cl_ptr_arr_sorted[set_offset + idx_curr_set] = cl_ptr_arr[i];
        idx_per_set[cl_ptr_arr[i]->cache_set] += 1;
    }

    // Build doubly linked list for every set
    for (uint32_t set = 0; set < ctx->sets; ++set) {
        set_offset = set * set_len;
        build_randomized_list_for_cache_set(ctx, cl_ptr_arr_sorted + set_offset);
    }

    // Relink the sets among each other
    uint32_t *idx_map = (uint32_t *) malloc(ctx->sets * sizeof(uint32_t));
    assert(idx_map);
    gen_random_indices(idx_map, ctx->sets);

    cacheline *curr_cl = cl_ptr_arr_sorted[idx_map[0] * set_len]->prev;
    cacheline *next_cl;

    for (uint16_t i = 0; i < ctx->sets; ++i) {
        curr_cl->next       = cl_ptr_arr_sorted[idx_map[(i + 1) % ctx->sets] * set_len];
        next_cl             = curr_cl->next->prev;
        curr_cl->next->prev = curr_cl;
        curr_cl             = next_cl;
    }

    cacheline *cache_ds = cl_ptr_arr_sorted[idx_map[0] * set_len];

    free(cl_ptr_arr_sorted);
    free(idx_per_set);
    free(idx_map);

    return cache_ds;
}

/*
 * Helper function to build a randomised list of cacheline structs for a set
 */
void build_randomized_list_for_cache_set(cache_ctx *ctx, cacheline **cacheline_ptr_arr)
{
    uint32_t len        = ctx->associativity;
    uint32_t *idx_map   = (uint32_t *) malloc(len * sizeof(uint32_t));
    assert(idx_map);
    gen_random_indices(idx_map, len);

    cacheline *curr_cl;
    for (uint16_t i = 0; i < len; ++i) {
        curr_cl         = cacheline_ptr_arr[idx_map[i]];
        curr_cl->next   = cacheline_ptr_arr[idx_map[(i + 1) % len]];
        curr_cl->prev   = cacheline_ptr_arr[idx_map[(len - 1 + i) % len]];

        // curr_cl->cache_set was already set before (depending on addressing)
        curr_cl->time_msrmt = 0;

        if (curr_cl == cacheline_ptr_arr[0]) {
            curr_cl->flags       = SET_FIRST(DEFAULT_FLAGS);
            curr_cl->prev->flags = SET_LAST(DEFAULT_FLAGS);
        }
        else {
            curr_cl->flags = curr_cl->flags | DEFAULT_FLAGS;
        }
    }

    free(idx_map);
}

/*
 * A heuristic to call before measurements to hopefully trigger
 * that the maximal (and thus fixed) processor frequenct is used.
 */
void prepare_measurement() {
    // busy loop for ~2s to get the cpu to max frequency on machines where it
    // cannot be fixed.
    uint64_t i = 0;
    while(i++ < 2 * PROCESSOR_FREQ);

    // Sample timestamp a few times because we sometimes observed slower values
    // on the first calls
    for (i = 0; i < 200; ++i) {
        rdtsc();
    }

    // Make sure all previous work terminated
    cpuid();
}
