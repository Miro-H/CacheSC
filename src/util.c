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
 * This file implements a collection of miscellaneous utilities. Some are useful
 * for library internal functions, some can be convenient for for external
 * users as well.
 */

#include "util.h"


// local functions
void swap(uint32_t *e1, uint32_t *e2);

/*
 * Sets the CPU affinity of the running process to the given parameter
 */
void pin_to_cpu(int cpu) {
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    assert(sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) >= 0);
}

void set_seed() {
    srand(time(NULL));
}

/*
 * Fills an array of the given length with random bytes.
 */
void gen_rand_bytes(unsigned char *arr, uint32_t arr_len) {
    for (uint32_t i = 0; i < arr_len; ++i) {
        arr[i] = rand() % 256;
    }
}

/*
 * Swap elements e1 and e2 of an array
 */
void swap(uint32_t *e1, uint32_t *e2) {
    uint32_t tmp = *e1;
    *e1 = *e2;
    *e2 = tmp;
}

/*
 * This computes a random permutation of the input array
 * using the Fisher-Yates shuffle algorithm
 */
void random_perm(uint32_t *arr, uint32_t arr_len) {
    uint32_t swap_idx;

    for (uint32_t i = arr_len - 1; i > 0; --i) {
        swap_idx = rand() % i;
        swap(arr + i, arr + swap_idx);
    }
}

/*
 * This creates an array of a random permutation of the indices 0, 1, ..., arr_len-1
 */
void gen_random_indices(uint32_t *arr, uint32_t arr_len) {
    for (uint32_t i = 0; i < arr_len; ++i) {
        arr[i] = i;
    }
    random_perm(arr, arr_len);
}

/*
 * Check if an element is in the given array
 */
bool is_in_arr(uint32_t elem, uint32_t *arr, uint32_t arr_len) {
    uint32_t i;

    for (i = 0; i < arr_len; ++i) {
        if (arr[i] == elem)
            return true;
    }

    return false;
}

/*
 * Calculate the average of an array
 */
double get_avg(uint32_t *arr, uint32_t arr_len) {
    double avg = 0;

    // Calculate the continuous average to avoid overflow issues
    for (uint32_t i = 0; i < arr_len; ++i) {
        avg = ((i * avg) + arr[i]) / (i + 1);
    }

    return avg;
}

/*
 * Return the maximum element of an array
 */
uint32_t get_max(uint32_t *arr, uint32_t arr_len) {
    uint32_t max = 0;

    for (uint32_t i = 0; i < arr_len; ++i) {
        if (arr[i] > max) {
            max = arr[i];
        }
    }

    return max;
}

/*
 * Return the minimum element of an array
 */
uint32_t get_min(uint32_t *arr, uint32_t arr_len) {
    uint32_t min = UINT32_MAX;

    for (uint32_t i = 0; i < arr_len; ++i) {
        if (arr[i] < min) {
            min = arr[i];
        }
    }

    return min;
}
