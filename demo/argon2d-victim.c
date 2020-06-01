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
 * This file implements a victim performing some password hashes with Argon2d.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <argon2.h>
#include <cachesc.h>


/*
 * Configure victim
 */
#define CPU_NUMBER 1

// Configure Argon2 hash
#define HASH_LEN 32
#define SALT_LEN 16
#define PWD_LEN 10

// local functions
void usage(const char *prog);

int main(int argc, char **argv)
{
    int sample_cnt = -1;
    uint32_t i;

    if (argc == 2)
        sample_cnt = atoi(argv[1]);
    if (sample_cnt < 0)
        usage(argv[0]);


    /*
     * Initial preparation
     */
    pin_to_cpu(CPU_NUMBER);

    uint8_t salt[SALT_LEN];
    memset( salt, 0x00, SALT_LEN );

    uint8_t pwd[PWD_LEN];
    uint8_t hash[PWD_LEN];
    gen_rand_bytes(pwd, PWD_LEN);

    // 1-pass computation, 64 mebibytes memory usage
    uint32_t t_cost = 2;
    uint32_t m_cost = (1<<16);
    uint32_t parallelism = 1;

    /*
     * Start computing "sample_cnt" Argon2d hashes
     */
    print_banner("Start Argon2d hashing");

    prepare_measurement();

    for (i = 0; i < sample_cnt; ++i) {
        argon2d_hash_raw(t_cost, m_cost, parallelism, pwd, PWD_LEN,
                         salt, SALT_LEN, hash, HASH_LEN);
    }

    print_banner("Stop Argon2d hashing");

    return EXIT_SUCCESS;
}

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <samples>\n", prog);
    exit(EXIT_FAILURE);
}
