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

import copy
import collections
import json
import re

from pprint import pprint

ModuleSection = collections.namedtuple("ModuleSection", ["name", "start", "end", "filename"])

r_MAPPINGS = re.compile(r"(0x[a-fA-F0-9]+)\s+(0x[a-fA-F0-9]+)\s+(0x[a-fA-F0-9]+)\s+(0x[a-fA-F0-9]+)\s+(.*)")
# 0xf7fd6114 - 0xf7fd6138 is .note.gnu.build-id in /lib/ld-linux.so.2
r_FILE_INFO = re.compile(r"(0x[a-fA-F0-9]+) - (0x[a-fA-F0-9]+) is ([^\s]+)( in .*)?")

# Collect backtraces from all threads
all_threads = False

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

files_with_bad_or_missing_code = {}

def get_code_context(location, filename):
    global files_with_bad_or_missing_code
    if filename == "" or filename in files_with_bad_or_missing_code:
        return None

    # Unfortunately due to a bug in GDB (I suspect)
    # Listing source code with `list loc1,loc1` to get a single line, breaks on header files
    # Hence we need to set the listsize 1. We don't want to open or interact with source code
    # directly as we don't want to be responsible for possibly messing with its filesystem state
    gdb.execute("set listsize 1", to_string=True)

    if isinstance(location, int):
        lines = gdb.execute("list *0x%x,*0x%x" % (location, location), to_string=True).splitlines()

        if len(lines) < 2:
            return None

        header = lines[0]

        if " is in " not in header:
            files_with_bad_or_missing_code[filename] = 1
            return None

        line = lines[1]
    else:
        lines = gdb.execute("list %s" % (location), to_string=True).splitlines()

        if len(lines) < 1:
            return None

        line = lines[0]

    # GDB list can still return lines even though there was an error
    # Filter out common error cases
    # will reject "warning: Source file is more recent than executable."
    match = re.match("^([0-9]+)\s(.*)$", line)

    if not match:
        files_with_bad_or_missing_code[filename] = 1
        return None

    lineno = int(match.group(1))
    code = match.group(2)

    if filename:
        # code not found
        if ("in %s" % (filename)) in code:
            files_with_bad_or_missing_code[filename] = 1
            return None

        # Some errorno print 
        if ("%s:" % (filename)) in code:
            files_with_bad_or_missing_code[filename] = 1
            return None

    return lineno, code

def capture_backtrace(primary=True, detailed=False):
    backtrace = []
    cframe = gdb.newest_frame()

    while cframe and cframe.is_valid():
        frame_info = {}
        decorator = gdb.FrameDecorator.FrameDecorator(cframe)

        fsym = cframe.function()

        section = find_section_from_pc(cframe.pc())

        # TODO: this will probably break when executing from dynamically allocated memory
        frame_info["address"] = cframe.pc()
        #frame_info["frame_type"] = frame_type_to_str(cframe.type())

        if section is not None:
            frame_info["relative_address"] = cframe.pc() - section.start
            frame_info["module"] = xstr(section.filename)

            if section.name != "":
                frame_info["module_address"] = '%s (%s)+0x%x'% (section.filename, section.name, frame_info["relative_address"])
            else:
                frame_info["module_address"] = '%s+0x%x'% (section.filename, frame_info["relative_address"])
        else:
            frame_info["relative_address"] = cframe.pc()
            frame_info["module"] = "??"
            frame_info["module_address"] = "0x%x" % (frame_info["relative_address"])

        sym_empty = {
            'function_name': '',
            'function_line': -1,
            'mangled_function_name': '',
            'function_signature': '',
            'callsite': [],
            'file': '',
            'line': -1,
            'args': [],
            'locals': [],
        }

        sym = copy.deepcopy(sym_empty)

        sym["function_name"] = xstr(cframe.name())

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

            # line information for inline functions is quite unreliable
            # technically the inline function doesn't exist. only debugging
            # information indicates that it is there
            if cframe.type() != gdb.INLINE_FRAME:
                sym["function_line"] = xint(fsym.line)

        sym["file"] = xstr(decorator.filename())

        if sym["file"] == frame_info["module"]:
            sym["file"] = ''

        sym["line"] = xint(decorator.line())

        if detailed:
            try:
                # make sure we can get a block. otherwise, there is no hope for listing code
                cframe.block()
                ctx_lines = 3

                for i in range(max(sym["line"]-ctx_lines+1, 1), sym["line"]+1):
                    lookup = "%s:%d"% (sym["file"], i)
                    result = get_code_context(lookup, sym["file"])

                    if result is None:
                        break

                    lineno, code = result

                    if lineno != i:
                        break

                    sym["callsite"] += [code.rstrip()]
            except RuntimeError as e:
                pass

            for v in xlist(decorator.frame_locals()):
                info = {}

                vsym = v.sym
                value = vsym.value(cframe)

                info["type"] = xstr(vsym.type)
                info["name"] = xstr(vsym.print_name)

                try:
                    info["value"] = xstr(value)
                except Exception as e:
                    info["value"] = "<%s>" % (str(e))

                sym["locals"] += [info]

            for v in xlist(decorator.frame_args()):
                info = {}

                vsym = v.sym
                value = vsym.value(cframe)

                info["type"] = xstr(vsym.type)
                info["name"] = xstr(vsym.print_name)

                try:
                    info["value"] = xstr(value)
                except Exception as e:
                    info["value"] = "<%s>" % (str(e))

                sym["args"] += [info]

        # don't include symbols or fields if they don't exist
        if sym != sym_empty:
            #print(pprint(sym), pprint(sym_empty))
            frame_info["symbol"] = {}
            for k, v in sym.items():
                if v != sym_empty[k]:
                    #print("ADD", k, v, sym_empty[k])
                    frame_info["symbol"][k] = v

            if "line" in frame_info["symbol"] and "file" not in frame_info["symbol"]:
                del frame_info["symbol"]["line"]

        backtrace += [frame_info]
        cframe = cframe.older()

    return backtrace

def backtrace_all():
    primary_thread = gdb.selected_thread()

    gdb_state = {}

    if primary_thread is None:
        # TODO: return error message
        return gdb_state

    pri_thread_info = {}
    pri_thread_info["tid"] = xint(primary_thread.num)
    pri_thread_info["backtrace"] = capture_backtrace(primary=True, detailed=True)
    gdb_state["primary_thread"] = pri_thread_info

    if all_threads:
        infe = gdb.selected_inferior()

        threads = []
        for thread in sorted(xlist(infe.threads()), key=lambda x: x.num):
            if thread.num == primary_thread.num:
                continue

            thread.switch()

            thread_info = {}
            thread_info["tid"] = xint(thread.num)
            thread_info["backtrace"] = capture_backtrace(primary=False, detailed=False)

            threads += [thread_info]

        if threads:
            gdb_state["threads"] = threads

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
