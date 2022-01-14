# Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
# 
# GDBTriage.py
# Collect crash information and emit as to JSON
# Developed for the AFLTriage project
import sys
import os

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

#  Name         Nr  Rel Offset    Size  Type            Groups
# eax           0    0      0       4 int32_t         general,all,save,restore
# NOTE: offset and type can have footnotes "*1", "*2" when the offset is inconsistent or the type name is NULL. See gdb/regcache.c for more info
r_REGISTER_LIST = re.compile(r"([^\s]+)\s+([0-9]+)\s+([0-9]+)\s+(\*?[0-9]+)\s+([0-9]+)\s+([^\s]+)\s+([^\s]+)")
r_REGISTER_VALUES = re.compile(r"([^\s]+)\s+(0x[a-fA-F0-9]+)\s+(.*)")

#### OPTIONS
# Collect backtraces from all threads
# TODO: make these into `gdbtriage` options
ALL_THREADS = False
FRAME_LIMIT=100

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

def u64(x):
    if sys.version_info >= (3,):
        return int(x)
    else:
        return long(x)

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

register_metadata = None
register_groups = None

def get_register_list():
    global register_metadata
    global register_groups

    if register_metadata:
        return register_metadata

    register_metadata = {}
    register_groups = {}

    lines = gdb.execute("maint print register-groups", to_string=True).splitlines()

    # skip header
    for line in lines[1:]:
        match = r_REGISTER_LIST.search(line)

        if not match:
            continue

        name, number, rel, offset, size, ty, groups = match.groups()

        number = int(number)
        rel = int(rel)
        # Footnote indicating error
        if offset.startswith("*"):
            offset = 0
        else:
            offset = int(offset)
        size = int(size)

        if size == 0:
            continue

        # Footnote indicating missing type
        if ty.startswith("*"):
            ty = ""

        groups = groups.split(",")

        rinfo = {
            "number": number,
            "rel": rel,
            "offset": offset,
            "size": size,
            "type": ty,
            "groups": groups
        }

        for g in groups:
            if g not in register_groups:
                register_groups[g] = [name]
            else:
                register_groups[g] += [name]

        register_metadata[name] = rinfo

    return register_metadata

def get_register_groups():
    if register_groups:
        return register_groups

    get_register_list()
    return register_groups

def get_primary_register_list():
    groups = get_register_groups()

    if "general" not in groups:
        return []

    return groups["general"]

def get_primary_register_values():
    primary_regs = get_primary_register_list()

    lines = gdb.execute("info registers general", to_string=True).splitlines()

    registers = []

    for line in lines:
        match = r_REGISTER_VALUES.search(line)

        if not match:
            continue

        name, hexval, pretty = match.groups()

        hexval = int(hexval, 16)

        if name not in primary_regs:
            continue

        rmeta = get_register_metadata(name)
        rinfo = {
            "name": name,
            "value": hexval,
            "pretty_value": pretty,
            "type": rmeta["type"],
            "size": rmeta["size"],
        }

        registers += [rinfo]

    return registers

def get_register_metadata(name):
    meta = get_register_list()
    if name not in meta:
        return None
    else:
        return meta[name]

def get_code_context(location, filename):
    global files_with_bad_or_missing_code
    if filename == "" or filename in files_with_bad_or_missing_code:
        return None

    filename_norm = filename

    if isinstance(location, int):
        lines = gdb.execute("list *0x%x,*0x%x" % (location, location), to_string=True).splitlines()

        if len(lines) < 2:
            return None

        header = lines[0]

        if " is in " not in header:
            files_with_bad_or_missing_code[filename] = 1
            files_with_bad_or_missing_code[filename_norm] = 1
            return None

        line = lines[1]
    else:
        # GDB 8.1.1 has a strange bug where looking up missing files with "../" in them causes a big delay
        # EX: /usr/lib/gcc/x86_64-linux-gnu/5.4.0/../../../../include/c++/5.4.0/bits/basic_string.tcc:221
        filename_norm = os.path.normpath(filename)
        location = location.replace(filename, filename_norm)
        lines = gdb.execute("list %s" % (location), to_string=True).splitlines()

        # Unknown error
        if len(lines) < 1:
            return None

        # Asking for source info can return MULTIPLE different paths that point to the same place
        # For example, in rust binaries:
        #
        # file: "/absolute/path/src/main.rs", line number: 683, symbol: "???"
        # 683                 let address = 0x012345usize;
        # file: "src/main.rs", line number: 683, symbol: "???"
        # 683                 let address = 0x012345usize;
        # 
        # Hence, the last line seems to be more reliable
        line = lines[-1]

    # GDB list can still return lines even though there was an error
    # Filter out common error cases
    # will reject "warning: Source file is more recent than executable."
    match = re.match("^([0-9]+)\s(.*)$", line)

    if not match:
        files_with_bad_or_missing_code[filename] = 1
        files_with_bad_or_missing_code[filename_norm] = 1
        return None

    lineno = int(match.group(1))
    code = match.group(2)

    if filename:
        banned_patterns = [
            # code not found
            "in %s" % (filename),
            "in %s" % (filename_norm),
            # Some errorno print
            "%s:" % (filename),
            "%s:" % (filename_norm),
        ]

        for bp in banned_patterns:
            if bp in code:
                files_with_bad_or_missing_code[filename] = 1
                files_with_bad_or_missing_code[filename_norm] = 1
                return None

    return lineno, code

def capture_backtrace(primary=True, detailed=False, frame_limit=0):
    backtrace = []
    cframe = gdb.newest_frame()
    frame_count = 0

    while cframe and cframe.is_valid():
        frame_count += 1
        if frame_limit and frame_count > frame_limit:
            break

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
                f_line = xint(fsym.line)
                if f_line > 0:
                    sym["function_line"] = f_line

        try:
            sym["file"] = xstr(decorator.filename())
        # Workaround known bug https://sourceware.org/bugzilla/show_bug.cgi?id=18984
        # Should be rare since it only occurs on a call to gdb.solib_name, which is a
        # fallback path if there isn't a DWARF file entry for this frame's PC. In that
        # case the file path would equal the module name, meaning it would be discarded
        # anyways (see below)
        except OverflowError:
            sym["file"] = ''

        # If no source file path found, GDB can return just the module name as a fallback
        # This isn't very helpful for source debugging so discard it
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

                info["type"] = xstr(vsym.type)
                info["name"] = xstr(vsym.print_name)

                try:
                    value = vsym.value(cframe)
                    info["value"] = xstr(value)
                except Exception as e:
                    info["value"] = "<%s>" % (str(e))

                sym["locals"] += [info]

            for v in xlist(decorator.frame_args()):
                info = {}

                vsym = v.sym

                info["type"] = xstr(vsym.type)
                info["name"] = xstr(vsym.print_name)

                try:
                    value = vsym.value(cframe)
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

def get_instruction_at(pc):
    try:
        insn = gdb.execute("x/1i 0x%x" % (pc), to_string=True).splitlines()[0]
        match = re.match("^(=> )?0x[0-9a-fA-F]+( <.*>)?:\s(.*)$", insn)

        if not match:
            return None

        insn = match.group(3)

        return insn.strip()
    except gdb.error:
        return None
    except gdb.MemoryError:
        return None

def get_stop_info():
    lines = gdb.execute("info program", to_string=True).splitlines()
    signal_name = "SIGUNKNOWN"

    for line in lines:
        if "It stopped at breakpoint" in line:
            signal_name = "SIGTRAP"
            break

        match = re.match(r"^It stopped with signal (SIG[^\s,]+),", line)
        if match:
            signal_name = match.group(1)
            break

    # This code could potentially fail if these fields are missing
    # Since they are really important, prefer to fail
    signo = int(gdb.parse_and_eval("$_siginfo.si_signo"))
    sicode = int(gdb.parse_and_eval("$_siginfo.si_code"))

    sinfo =  {"signal_name": signal_name, "signal_number": signo, "signal_code": sicode}

    # https://man7.org/linux/man-pages/man2/sigaction.2.html
    if signal_name in ["SIGSEGV", "SIGILL", "SIGBUS", "SIGFPE", "SIGTRAP"]:
        sinfo["faulting_address"] = u64(gdb.parse_and_eval("$_siginfo._sifields._sigfault.si_addr")) & u64(0xffffffffffffffff)

    return sinfo

def get_thread_stop_context(primary_thread):
    gdb_state = {}

    assert primary_thread

    pri_thread_info = {}
    pri_thread_info["tid"] = xint(primary_thread.num)
    pri_thread_info["backtrace"] = capture_backtrace(primary=True, detailed=True, frame_limit=FRAME_LIMIT)

    regs = get_primary_register_values()
    if regs:
        pri_thread_info["registers"] = regs

    if len(pri_thread_info["backtrace"]):
        first_frame = pri_thread_info["backtrace"][0]
        insn = get_instruction_at(first_frame["address"])

        if insn:
            pri_thread_info["current_instruction"] = insn

    gdb_state["primary_thread"] = pri_thread_info

    # having extra thread information is optional
    if ALL_THREADS:
        infe = gdb.selected_inferior()

        threads = []
        for thread in sorted(xlist(infe.threads()), key=lambda x: x.num):
            if thread.num == primary_thread.num:
                continue

            thread.switch()

            thread_info = {}
            thread_info["tid"] = xint(thread.num)
            thread_info["backtrace"] = capture_backtrace(primary=False, detailed=False, frame_limit=FRAME_LIMIT)

            threads += [thread_info]

        if threads:
            gdb_state["other_threads"] = threads

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

def get_current_architecture():
    if hasattr(gdb.selected_inferior(), "architecture"):
        return gdb.selected_inferior().architecture().name()
    else:
        match = re.search(r"(\(currently ([^)]+)\))|(assumed to be (.+))", gdb.execute("show architecture", to_string=True))
        if match is None:
            return "UNKNOWN"

        arch = match.group(2)
        return arch

def get_arch_info():
    bits = int(gdb.parse_and_eval("sizeof($pc)"))*8
    if bits == 0:
        bits = 32

    v = {
       "address_bits": bits,
       "architecture": get_current_architecture(),
    }

    return v

class GDBTriageCommand(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, "gdbtriage", gdb.COMMAND_OBSCURE)

    def invoke(self, argstr, from_tty):
        if not hasattr(gdb, "FrameDecorator"):
            raise ImportError("GDB 7.10 and above must be used")

        # Unfortunately due to a bug in GDB (I suspect)
        # Listing source code with `list loc1,loc1` to get a single line, breaks on header files
        # Hence we need to set the listsize 1. We don't want to open or interact with source code
        # directly as we don't want to be responsible for possibly messing with its filesystem state
        gdb.execute("set listsize 1", to_string=True)

        # XXX: only do this on i386/x86_64
        gdb.execute("set disassembly-flavor intel", to_string=True)

        # XXX: undo "set"'s to restore GDB state
        primary_thread = gdb.selected_thread()

        # Target or doesn't exist!
        if primary_thread is not None:
            # Assumes success. Failures should be handled internally. Otherwise throw
            response = { "result": "SUCCESS" }

            ctx = get_thread_stop_context(primary_thread)
            ctx["arch_info"] = get_arch_info()
            # we must have stop info
            # TODO: handle other platforms (non Linux) stop info
            ctx["stop_info"] = get_stop_info()

            response["context"] = ctx
        else:
            response = {"result": "ERROR_TARGET_NOT_RUNNING"}

        print(json.dumps(response))

GDBTriageCommand()
