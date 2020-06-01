#!/usr/bin/env python3

#
# This file is part of the plotting scripts supporting the CacheSC library
# (https://github.com/Miro-H/CacheSC), which implements Prime+Probe attacks on
# virtually and physically indexed caches.
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
# Parser class to parse log files of a certain layout and extract the timing
# information used for plotting.
#

import re

from types import SimpleNamespace
from collections import namedtuple
from enum import Enum

from logger import Logger, LogLevel

ConfEntry = namedtuple("ConfEntry", "default type pattern")

class LogFile(Enum):
    DEFAULT     = 1

class Parser:
    def __init__(self, log_level=LogLevel.NORMAL):
        self.logger = Logger("parser", log_level)

    def extract_if_present(self, line, pattern, curr_val, default_val, type_conv):
        if curr_val == default_val:
            match = re.search(pattern, line)
            if match:
                return type_conv(match.groups()[0])
        return curr_val

    def parse_samples(self, fp, sample_cnt, sample_size):
        while True:
            line = fp.readline()
            if "Sample" in line:
                break

        round_cnt   = sample_cnt
        samples     = []

        # Parse samples
        while "Sample" in line:
            round_cnt -= 1
            if round_cnt < 0:
                self.logger.error(f"More than the expected {sample_cnt} samples!")

            line    = fp.readline().rstrip()
            sample  = list(map(int, line.split()))
            if len(sample) != sample_size:
                self.logger.error(
                    f"Received {len(sample)}/{sample_size} measurements for " \
                    f"sample number {len(samples)}:\n{sample}"
                )
            samples.append(sample)

            line = fp.readline()

        return samples, line

    def parse_meta_data_internal(self, meta_data_conf, log_file):
        line = log_file.readline()

        # Init
        meta_data = {}
        for key, entry in meta_data_conf.items():
            meta_data[key] = entry.default

        # Parse metadata first
        self.logger.line("Parse metadata")
        while "Output" not in line:
            for key in meta_data.keys():
                meta_data[key] = self.extract_if_present(
                                    line, meta_data_conf[key].pattern,
                                    meta_data[key], meta_data_conf[key].default,
                                    meta_data_conf[key].type
                                 )

            line = log_file.readline()

        return meta_data

    def parse_default(self, log_file, do_normalize):
        meta_data_conf = {
            "samples_cnt":       ConfEntry(0, int, "Number of samples: (.+)"),
            "msrmts_per_sample": ConfEntry(0, int, "Measurements per sample: (.+)"),
            "legend":            ConfEntry("", str, "Legend: (.+)"),
            "x_axis_label":      ConfEntry("cache set", str, "x-axis label: (.+)"),
            "y_axis_label":      ConfEntry("avg access cycle count", str,
                                    "y-axis label: (.+)"),
        }

        meta_data = self.parse_meta_data_internal(meta_data_conf, log_file)

        samples_cnt         = meta_data['samples_cnt']
        msrmts_per_sample   = meta_data['msrmts_per_sample']

        bl_samples = None
        if do_normalize:
            self.logger.line(
                f"Parse {samples_cnt}x{msrmts_per_sample} data baseline "
                 "measurements"
            )
            bl_samples, _ = self.parse_samples(
                                log_file, samples_cnt, msrmts_per_sample
                            )

        self.logger.line(f"Parse {samples_cnt}x{msrmts_per_sample} data samples")

        samples, last_line = self.parse_samples(
                                log_file, samples_cnt, msrmts_per_sample
                             )

        if last_line != "":
            self.logger.warning(
                f"Trailing data after samples:\n{last_line + log_file.read()}"
            )

        return samples, bl_samples, SimpleNamespace(**meta_data)

    def parse(self, file_path, do_normalize=False, file_type=LogFile.DEFAULT):
        self.logger.line(f"Parse log file {file_path}")

        with open(file_path, "r") as log_file:
            if file_type == LogFile.DEFAULT:
                return self.parse_default(log_file, do_normalize)
            else:
                self.logger.error("Unknown log file type.")
