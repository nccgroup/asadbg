#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# This GDB script is a wrapper on top of libptmalloc/libptmalloc2.py
# except that we automatically detect what ASA version we are debugging
# and pass libptmalloc the right arena/etc. addresses.

import os
import sys
import traceback
import re

# Our own libraries
cwd = os.getcwd()
sys.path.insert(0, cwd)
import importlib
import helper_gdb as hgdb
importlib.reload(hgdb)
sys.path.insert(0, os.path.join(cwd, "libptmalloc"))
import libptmalloc2 as libpt
importlib.reload(libpt)

class logger:
    def logmsg(self, s, end=None):
        if type(s) == str:
            if end != None:
                print("[asa_libptmalloc] " + s, end=end)
            else:
                print("[asa_libptmalloc] " + s)
        else:
            print(s)

# hardcoded symbols for ASAv glibc.so so we don't have to remember them
# tip to easily find main_arena:
# it is the first global accessed in glibc.so libc_get_largest_contig_free_mem()
# XXX We could actually parse the output to get the address of main_arena from gdb :)
#(gdb) x /5i libc_get_largest_contig_free_mem 
#   0x7ffff4943910 <libc_get_largest_contig_free_mem>:	push   rbp
#   0x7ffff4943911 <libc_get_largest_contig_free_mem+1>:	lea    r10,[rip+0x328d08]        # 0x7ffff4c6c620
#   0x7ffff4943918 <libc_get_largest_contig_free_mem+8>:	xor    r8d,r8d
#   0x7ffff494391b <libc_get_largest_contig_free_mem+11>:	mov    ebp,0x1
#   0x7ffff4943920 <libc_get_largest_contig_free_mem+16>:	push   rbx
# As we have:
# .data:00007FFFF4C6C620 main_arena    
pt_global_symbols = {
    "asa962-7-smp-k8.bin":{
        "main_arena": 0x7ffff4c9b620,
        "mp_": 0x7ffff4c9b160,
    },
    "asav941-200.qcow2":{
        "main_arena": 0x00000036559A8620,
        "mp_": 0x00000036559A8160,
    },
    "asav962-7.qcow2":{
        "main_arena": 0x7ffff4c9b620,
        "mp_": 0x7ffff4c9b160,
    },
    "asav981-5.qcow2":{
        "main_arena": 0x7ffff4c6c620,
    },
    # below does not work because dlmalloc used in lina itself
    #(gdb) ptmalloc
    #[!] No arenas could be correctly guessed.
    #[!] Nothing was found at 0xdc095140
    "asa924-k8.bin":{
        "main_arena": 0xdc095140,
        "mp_": 0xdc0955a0,
    },
}

class ptsymbols(gdb.Command):
    help_str = "ptsymbols  : show ptmalloc symbols"

    def __init__(self):
        super(ptsymbols, self).__init__("ptsymbols", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):

        log = logger()

        bin_name = hgdb.get_info()
        log.logmsg("firmware name: %s" % bin_name)

        try:
            pt_symbols = pt_global_symbols[bin_name]
            if pt_symbols != None:
                log.logmsg("pt_symbols:")
                for k in pt_symbols.keys():
                    log.logmsg("  %s: 0x%x" % (k, pt_symbols.get(k)))
        except Exception:
            log.logmsg("pt_symbols failed to initalize, add target to pt_global_symbols")

if __name__ == "__main__":

    log = logger()
    ptsymbols()
    help_extra = ptsymbols.help_str

    pth = libpt.pt_helper()
    libpt.pthelp(pth, help_extra)
    libpt.ptchunk(pth)
    libpt.ptcallback(pth)
    libpt.ptarena(pth)
    libpt.ptsearch(pth)
    libpt.ptstats(pth)
    libpt.ptbin(pth)
    libpt.ptarenaof(pth)
    libpt.ptscanchunks(pth)

    log.logmsg("loaded")
