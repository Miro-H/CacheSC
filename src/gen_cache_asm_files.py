#!/usr/bin/env python3

#
# This file is part of the CacheSC library (https://github.com/Miro-H/CacheSC),
# which implements Prime+Probe attacks on virtually and physically indexed
# caches.
#
# Copyright (C) 2020  Miro Haller
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Contact: miro.haller@alumni.ethz.ch
#
# Short description of this file:
# This script generates inlined assembly code in C files.
# The justification is that the unrolled assembly code depends on the
# size of the cache and can therefore not be prepared statically.
#

import re
import os

from textwrap import dedent


CACHE_LEVELS    = ["L1", "L2"]

CONF_FNAME          = "device_conf.h"
CACHE_TYPES_FNAME   = "cache_types.h"
START_TIMER_FN      = "start_timer"
STOP_TIMER_FN       = "stop_timer"

def extract_macro(macro_name, lines, type_conv=int):
    pattern = f"#define\s+{macro_name}\s+(.*)\n"

    for line in lines:
        match = re.search(pattern, line)
        if match:
            return type_conv(match.groups()[0])

#
# Parse general config file
#
with open(CACHE_TYPES_FNAME, "r") as gen_conf_fp:
    lines = gen_conf_fp.readlines()

    CL_NEXT_OFFSET  = extract_macro("CL_NEXT_OFFSET", lines)
    CL_PREV_OFFSET  = extract_macro("CL_PREV_OFFSET", lines)

for cache_level in CACHE_LEVELS:
    cache_level_lowercase = cache_level.lower()

    #
    # Parse config file
    #
    with open(CONF_FNAME, "r") as conf_fp:
        lines = conf_fp.readlines()

        SETS            = extract_macro(f"{cache_level}_SETS", lines)
        ASSOCIATIVITY   = extract_macro(f"{cache_level}_ASSOCIATIVITY", lines)

    assert(ASSOCIATIVITY >= 4 and ASSOCIATIVITY % 2 == 0)

    #
    # Generate C file with repetitive inlined assembly code
    #
    header = dedent(f"""\
        /*
         * This file is generated by {os.path.basename(__file__)}.
         * MODIFICATIONS WILL THUS BE OVERWRITTEN.
         */

        #ifndef HEADER_{cache_level}_ASM_H
        #define HEADER_{cache_level}_ASM_H

        #include "asm.h"
        #include "cache.h"
        #include "{CONF_FNAME}"

        """
    )

    footer = f"\n#endif // HEADER_{cache_level}_ASM_H"

    probe_cacheset = dedent(f"""
        // Traverse cache sets in reverse order for minimal cache impact
        static inline cacheline *asm_{cache_level_lowercase}_probe_cacheset(cacheline *curr_cl) {{
            cacheline *next_cl;

            {START_TIMER_FN}();
            asm volatile(
                "mov {CL_PREV_OFFSET}(%[curr_cl]), %%rax \\n\\t"
                "mov {CL_PREV_OFFSET}(%%rax), %%rcx \\n\\t"
        """
    )

    # The following weird indentation is necessary that the generated C file
    # is correctly indented
    probe_cacheset += f"""\
        "mov {CL_PREV_OFFSET}(%%rcx), %%rax \\n\\t"
        "mov {CL_PREV_OFFSET}(%%rax), %%rcx \\n\\t"
""" * ((ASSOCIATIVITY - 4) // 2)

    probe_cacheset += dedent(f"""\
                "mov {CL_PREV_OFFSET}(%%rcx), %[curr_cl_out] \\n\\t"
                "mov {CL_PREV_OFFSET}(%[curr_cl_out]), %[next_cl_out] \\n\\t"
                : [next_cl_out] "=rm" (next_cl), [curr_cl_out] "=rm" (curr_cl)
                : [curr_cl] "r" (curr_cl)
                : "%rax", "%rcx"
            );
            {STOP_TIMER_FN}(&(curr_cl->time_msrmt));

            return next_cl;
        }}
        """
    )

    prime = dedent(f"""\
        static inline cacheline *asm_{cache_level_lowercase}_prime(cacheline *curr_cl) {{
            cpuid();

            asm volatile(
                "mov {CL_NEXT_OFFSET}(%[curr_cl]), %%rax \\n\\t"
                "lfence \\n\\t"
                "mov {CL_NEXT_OFFSET}(%%rax), %%rcx \\n\\t"
        """
    )

    prime += f"""\
        "mov {CL_NEXT_OFFSET}(%%rcx), %%rax \\n\\t"
        "lfence \\n\\t"
        "mov {CL_NEXT_OFFSET}(%%rax), %%rcx \\n\\t"
        """ * ( (SETS * ASSOCIATIVITY - 4) // 2)

    prime += dedent(f"""\
                "mov {CL_NEXT_OFFSET}(%%rcx), %%rax \\n\\t"
                "lfence \\n\\t"
                "mov {CL_NEXT_OFFSET}(%%rax), %[curr_cl_out] \\n\\t"
                : [curr_cl_out] "=rm" (curr_cl)
                : [curr_cl] "r" (curr_cl)
                : "%rax", "%rcx"
            );
            cpuid();

            return curr_cl->prev;
        }}
        """
    )

    with open(f"{cache_level_lowercase}_asm.h", "w+") as asm_fp:
        asm_fp.write(header)
        asm_fp.write(probe_cacheset)
        #asm_fp.write(prime)
        asm_fp.write(footer)