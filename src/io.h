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
 * This file contains helper functions for well-arranged console output,
 * as well as post-processing compatible writing writing of log files.
 */

#ifndef HEADER_IO_H
#define HEADER_IO_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define PRINT_FLUSH(fmt, ...) \
    printf(fmt, ## __VA_ARGS__); \
    fflush(stdout)

#define PRINT_LINE(fmt, ...) PRINT_FLUSH(INDENT(fmt), ## __VA_ARGS__)

#define BANNER_LEN 60
#define BANNER "################################################################\n"
#define INDENT(msg) "#### " msg

/*
 * Prints a message in a banner.
 * The `msg` should be <= 60 characters long and without line breaks.
 */
static void print_banner(const char *msg) {
    int msg_len     = strlen(msg);
    int left_pad    = (BANNER_LEN - msg_len + 1) / 2;
    int right_pad   = (BANNER_LEN - msg_len) / 2;

    printf(BANNER);
    printf("# %*s%*s #\n", left_pad + msg_len, msg, right_pad, "");
    PRINT_FLUSH(BANNER);
}

/*
 * Print an integer as a hex string.
 */
static void print_hex(const char *str, uint16_t str_len) {
    for (uint16_t i = 0; i < str_len; ++i) {
        printf("%02x", (const unsigned char) str[i]);
    }
    fflush(stdout);
}

/*
 * Print the results of the cache attack measurements in the format
 * that is expected by the post-processing parsing scripts.
 */
static void print_results(uint32_t *res, uint32_t sample_cnt,
                         uint32_t sets_per_sample)
{
   for (uint32_t i = 0; i < sample_cnt; ++i) {
        PRINT_LINE("Sample number %d:\n", i);

        for (uint32_t j = 0; j < sets_per_sample; ++j) {
            printf("%3d ", res[i * sets_per_sample + j]);
        }
        putchar('\n');
    }
    fflush(stdout);
}

#endif // HEADER_IO_H
