# Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
# 
# GDB Triage to JSON Script
# by Grant Hernandez
import sys

try:
    import gdb
except ImportError:
    print("Script expected to be running from GDB that supports python")
    sys.exit(1)

import collections
import json
import re

from pprint import pprint

ModuleSection = collections.namedtuple("ModuleSection", ["name", "start", "end", "filename"])

r_MAPPINGS = re.compile(r"(0x[a-fA-F0-9]+)\s+(0x[a-fA-F0-9]+)\s+(0x[a-fA-F0-9]+)\s+(0x[a-fA-F0-9]+)\s+(.*)")
# 0xf7fd6114 - 0xf7fd6138 is .note.gnu.build-id in /lib/ld-linux.so.2
r_FILE_INFO = re.compile(r"(0x[a-fA-F0-9]+) - (0x[a-fA-F0-9]+) is ([^\s]+)( in .*)?")

"""
######################
## Utility functions
######################
"""
def xstr(s):
    return '' if s is None else str(s)

def xint(s):
    return -1 if s is None else int(s)

def xlist(s):
    if s is None:
        return []

    if isinstance(s, tuple):
        s = list(s)

    if not isinstance(s, list):
        return []

    return s

"""
######################
## Triage functions
######################
"""

def _solib_from_frame(frame):
    symtab_line = frame.find_sal()

    if symtab_line is None or not symtab_line.is_valid():
        return None

    symtab = symtab_line.symtab

    if symtab is None or not symtab.is_valid():
        return None

    return symtab.objfile.filename

def capture_backtrace(detailed=False):
    backtrace = []
    cframe = gdb.newest_frame()

    while cframe and cframe.is_valid():
        frame_info = {}
        decorator = gdb.FrameDecorator.FrameDecorator(cframe)

        fsym = cframe.function()

        section = find_section_from_pc(cframe.pc())

        # TODO: this will probably break when executing from dynamically allocated memory
        frame_info["address"] = cframe.pc()

        if section is not None:
            frame_info["relative_address"] = cframe.pc() - section.start
            frame_info["module"] = xstr(section.filename)
            frame_info["pretty_address"] = '%s%s+0x%x'% (section.filename, section.name, frame_info["relative_address"])
        else:
            frame_info["relative_address"] = cframe.pc()
            frame_info["module"] = "??"
            frame_info["pretty_address"] = "0x%x" % (frame_info["relative_address"])

        sym = {}
        sym["function_name"] = xstr(cframe.name())
        sym["mangled_function_name"] = ''
        sym["function_signature"] = ''

        # TODO: only include symbol information when we actually have symbols
        if fsym is not None:
            # NOTE: this is kinda broken on all current GDBs (always returns linkage name)
            # See https://sourceware.org/bugzilla/show_bug.cgi?id=12707
            linkage_name = xstr(fsym.linkage_name)
            paren = linkage_name.find("(")
            if paren != -1:
                linkage_name = linkage_name[:paren]

            # don't bother including linkage names if they aren't really mangled
            if '::' not in linkage_name:
                sym["mangled_function_name"] = linkage_name

            sym["function_signature"] = xstr(fsym.type)

        sym["file"] = xstr(decorator.filename())

        if sym["file"] == frame_info["module"]:
            sym["file"] = ''

        sym["line"] = xint(decorator.line())

        frame_info["symbol"] = sym

        frame_info["args"] = []
        frame_info["locals"] = []

        if detailed:
            for v in xlist(decorator.frame_locals()):
                info = {}

                sym = v.sym
                value = sym.value(cframe)

                info["type"] = xstr(sym.type)
                info["name"] = xstr(sym.print_name)
                info["value"] = xstr(value)

                frame_info["locals"] += [info]

            for v in xlist(decorator.frame_args()):
                info = {}

                sym = v.sym
                value = sym.value(cframe)

                info["type"] = xstr(sym.type)
                info["name"] = xstr(sym.print_name)
                info["value"] = xstr(value)

                frame_info["args"] += [info]

        backtrace += [frame_info]
        cframe = cframe.older()

    return backtrace

def backtrace_all():
    primary_thread = gdb.selected_thread()

    gdb_state = {}

    gdb_state["current_tid"] = -1
    gdb_state["threads"] = []

    if primary_thread is None:
        # TODO: return error message
        return gdb_state

    gdb_state["current_tid"] = xint(primary_thread.num)

    infe = gdb.selected_inferior()

    for thread in sorted(xlist(infe.threads()), key=lambda x: x.num):
        thread.switch()

        thread_info = {}
        thread_info["tid"] = xint(thread.num)
        thread_info["backtrace"] = capture_backtrace()

        gdb_state["threads"] += [thread_info]

    return gdb_state

def find_section_from_pc(pc):
    # binary search assumes sections are sorted ascending by start
    sections = get_module_sections()

    l = 0
    r = len(sections)-1

    while l <= r:
        m = (r+l)//2

        sec = sections[m]

        if pc < sec.start:
            r = m-1
        elif pc > sec.end:
            l = m+1
        else:
            return sec

    return None

sections_cache = None

def get_module_sections():
    global sections_cache

    if sections_cache:
        return sections_cache

    sections = []
    lines = gdb.execute("info files", to_string=True).splitlines()

    start_addrs = {}

    for line in lines:
        line = line.strip()

        match = r_FILE_INFO.search(line)

        if not match:
            continue

        start, end, section_name, filename = match.groups()

        start = int(start, 16)
        end = int(end, 16)

        # we have a filename or DSO
        if filename is None:
            filename = get_primary_module_path()
        else:
            filename = filename[len(" in "):]

            # avoid capturing VDSO
            if "system-supplied DSO" in filename:
                continue

        start_addrs[start] = 1
        sections += [ModuleSection(section_name, start, end, filename)]

    # `info files` can be missing info when the ELF file is fully stripped
    lines = gdb.execute("info proc mappings", to_string=True).splitlines()

    for line in lines:
        line = line.strip()

        # get every named section
        match = r_MAPPINGS.search(line)

        if not match:
            continue

        start, end, size, offset, name = match.groups()

        start = int(start, 16)
        end = int(end, 16)
        size = int(size, 16)
        offset = int(offset, 16)

        if start in start_addrs:
            continue

        if name.strip() == "":
            continue

        mod = ModuleSection("", start, end, name)
        sections += [mod]

    sections = sorted(sections, key=lambda x: x.start)
    sections_cache = sections
    return sections

def get_primary_module_path():
    return gdb.progspaces()[0].filename

def main():
    if not hasattr(gdb, "FrameDecorator"):
        raise ImportError("GDB 7.10 and above must be used")

    bt = backtrace_all()

    print(json.dumps(bt))

main()
