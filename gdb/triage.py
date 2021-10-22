# Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
# GDB Triage Script
import gdb
import collections
import json

from pprint import pprint

ModuleSection = collections.namedtuple("ModuleSection", ["name", "start", "end", "filename"])

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

    for line in lines:
        line = line.strip()

        if not line:
            break

        if not line.startswith("0x"):
            continue

        blobs = [x.strip() for x in line.split(" ")]
        addr_start = int(blobs[0], 16)
        addr_end = int(blobs[2], 16)
        section_name = blobs[4]

        if len(blobs) == 7:
            filename = blobs[6]
        else:
            filename = get_primary_module_path()

        sections += [ModuleSection(section_name, addr_start, addr_end, filename)]

    sections = sorted(sections, key=lambda x: x.start)
    sections_cache = sections
    return sections

def get_primary_module_path():
    return gdb.progspaces()[0].filename

def main():
    if not hasattr(gdb, "FrameDecorator"):
        raise ImportError("GDB 7.10 and above must be used")

    bt = backtrace_all()

    #for obj in gdb.objfiles():
        #print(str(obj), str(obj.filename), str(obj.__dict__))
    #for obj in gdb.progspaces():
        #print(str(obj), str(obj.filename), str(obj.__dict__))

    #pprint(get_module_sections())
    #pprint(bt)
    print(json.dumps(bt))

main()
