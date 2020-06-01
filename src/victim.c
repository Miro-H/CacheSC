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
 * This file contains functions to prepare victim data structure(s) to test
 * P+P attacks.
 */

#include "victim.h"

/*
 * This prepares a cache line that is in a given set. This can be used to mimic
 * the access of a single cache line.
 * In case of unprivileged physical access, the target set is only accurate modulo
 * the CACHE_GROUP_SIZE.
 */
cacheline *prepare_victim(cache_ctx *ctx, uint32_t target_set) {
    cacheline *victim_set_ds    = prepare_cache_set_ds(ctx, &target_set, 1);
    cacheline *victim_cl        = victim_set_ds;

    // Free the other lines in the same set that are not used.
    if (ctx->addressing == PHYSICAL) {
        cacheline *curr_cl = victim_cl->next;
        cacheline *next_cl;

        do {
            next_cl = curr_cl->next;
            // Here, it is ok to free them directly, as every line in the same
            // set is from a different page anyway.
            free(remove_cache_group_set(curr_cl));
            curr_cl = next_cl;
        } while(curr_cl != victim_cl);
    }

    return victim_cl;
}

/*
 * Release the victim, taking into account with which method it was allocated
 */
void release_victim(cache_ctx *ctx, cacheline *victim_cl) {
    if (ctx->addressing == VIRTUAL) {
        free(remove_cache_set(ctx, victim_cl));
    }
    else {
        free(remove_cache_group_set(victim_cl));
    }
}
