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
 * This file defines a collection of miscellaneous utilities. Some are useful
 * for library internal functions, some can be convenient for for external
 * users as well.
 */

#ifndef HEADER_UTIL_H
#define HEADER_UTIL_H

#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

#include <assert.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

void pin_to_cpu(int cpu);

void set_seed(void);
void gen_rand_bytes(unsigned char *arr, uint32_t arr_len);
void random_perm(uint32_t *arr, uint32_t arr_len);
void gen_random_indices(uint32_t *arr, uint32_t arr_len);

bool is_in_arr(uint32_t elem, uint32_t *arr, uint32_t arr_len);

double get_avg(uint32_t *arr, uint32_t arr_len);
uint32_t get_max(uint32_t *arr, uint32_t arr_len);
uint32_t get_min(uint32_t *arr, uint32_t arr_len);

#endif // HEADER_UTIL_H
