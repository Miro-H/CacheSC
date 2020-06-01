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
# Logger class, providing fancy output printing and different log levels.
#

from colorama import Fore, Style
from enum import IntEnum


# Constants
TITLE_LINE_LEN  = 64
MAX_LINE_LENGTH = TITLE_LINE_LEN - 4
TITLE_SEP       = "#" * TITLE_LINE_LEN
INDENT_LEN      = 4

class LogLevel(IntEnum):
    SILENT  = 0
    NORMAL  = 1
    VERBOSE = 2

class Logger:
    def __init__(self, name, log_level=LogLevel.NORMAL):
        self.name       = f"[{name}]: "
        self.log_level  = log_level

    def set_verbose(self):
        self.log_level = LogLevel.VERBOSE

    def print_tagged(self, out):
        print(f"{self.name}" + out.replace("\n", f"\n{self.name}"))

    def error(self, msg):
        self.print_tagged(f"{Fore.RED}ERROR: {msg}{Style.RESET_ALL}")
        exit(1)

    def warning(self, msg):
        if self.log_level > LogLevel.SILENT:
            self.print_tagged(f"{Fore.YELLOW}WARNING: {msg}{Style.RESET_ALL}")

    def title(self, title):
        if self.log_level > LogLevel.SILENT:
            self.print_tagged(TITLE_SEP)
            for i in range(0, len(title), MAX_LINE_LENGTH):
                content = title[i:i+MAX_LINE_LENGTH].center(MAX_LINE_LENGTH)
                self.print_tagged(f"# {content} #")
            self.print_tagged(TITLE_SEP)

    def line(self, line):
        if self.log_level > LogLevel.SILENT:
            indent = "#" * INDENT_LEN
            self.print_tagged(f"{indent} {line}")

    def debug(self, s):
        if self.log_level >= LogLevel.VERBOSE:
            self.print_tagged(f"[DEBUG]: {s}")
