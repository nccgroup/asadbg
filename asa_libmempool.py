#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# This GDB script is a wrapper on top of libmempool/libmempool_gdb.py
# except that we automatically detect what ASA version we add an additional
# `mpsymbol` command that can be used to dump out the symbols, if known

import os
import sys
import importlib

# Our own libraries
cwd = os.getcwd()
sys.path.insert(0, cwd)
import helper_gdb as hgdb
importlib.reload(hgdb)
import helper as h
importlib.reload(h)
sys.path.insert(0, os.path.join(cwd, "libmempool"))
import libmempool_gdb as lmp_gdb
importlib.reload(lmp_gdb)

class logger:
    def logmsg(self, s, end=None):
        if type(s) == str:
            if end != None:
                print("[asa_libmempool] " + s, end=end)
            else:
                print("[asa_libmempool] " + s)
        else:
            print(s)

# hardcoded symbols so we don't have to remember them
# these could also be based on mempool_array like in libdlmalloc
mp_global_symbols = {
    "asav962-7.qcow2":{
        "mp_mstate": 0x7ffff7ff73c0
    },
    "asav941-200.qcow2":{
        "mp_mstate": 0x7ffff6e273c0,
    },
    "asa924-k8.bin":{
        "mp_mstate" : 0xa84001e4,
    },
    "asa912-smp-k8.bin":{
        "mp_mstate" : 0x7fff1ebf73b8,
    },
}

class mpsymbols(gdb.Command):
    help_str = "mpsymbols   : show ASA mempool symbols"

    def __init__(self):
        super(mpsymbols, self).__init__("mpsymbols", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

        self.initOK = False
        self.libdl = None
        self.target = None
        self.mh_version = None
        
        self.log = logger()
        try:
            targetdb = os.environ["ASADBG_DB"]
        except:
            self.log.logmsg("You need to define ASADBG_DB first")
            exit()
        self.bin_name = hgdb.get_info()
        self.log.logmsg("firmware name: %s" % self.bin_name)
        targets = h.load_targets(targetdb)
        for t in targets:
            if t["fw"] == self.bin_name:
                self.target = t
                break
        
        if not self.target:
            self.log.logmsg("[!] Could not find bin name in targets")
            return
        
        if "heap_alloc" not in self.target.keys():
            self.log.logmsg("[!] Could not find heap alloc in target, defaulting to mempool header v2")
            self.mh_version = lmp_gdb.lmp.MEMPOOL_VERSION_2
        else:
            if "dlmalloc 2.8" in self.target["heap_alloc"] or \
               "ptmalloc" in self.target["heap_alloc"]:
                self.log.logmsg("Detected mempool header v2")
                self.mh_version = lmp_gdb.lmp.MEMPOOL_VERSION_2
            elif "dlmalloc 2.6" in self.target["heap_alloc"]:
                self.log.logmsg("Detected mempool header v1")
                self.mh_version = lmp_gdb.lmp.MEMPOOL_VERSION_1
            else:
                self.log.logmsg("[!] Need to add support for new heap alloc for detecting mempool header version?")
                return

        self.initOK = True

    def invoke(self, arg, from_tty):    
        if not self.initOK:
            self.log.logmsg("[!] Could not use mpsymbols")
            return
        
        try:
            mp_symbols = mp_global_symbols[self.bin_name]
            if mp_symbols != None:
                self.log.logmsg("mp_symbols:")
                for k in mp_symbols.keys():
                    self.log.logmsg("  %s: 0x%x" % (k, mp_symbols.get(k)))
        except:
            self.log.logmsg("mp_symbols failed to initalize, consider adding target to mp_global_symbols")

if __name__ == "__main__":

    log = logger()
    mps = mpsymbols()
    help_extra = mpsymbols.help_str

    lmp_gdb.mphelp(mh_version=mps.mh_version, help_extra=help_extra)
    lmp_gdb.mpbinwalk(mh_version=mps.mh_version)
    lmp_gdb.mpheader(mh_version=mps.mh_version)
    lmp_gdb.mpbin(mh_version=mps.mh_version)
    lmp_gdb.mpmstate(mh_version=mps.mh_version)
    lmp_gdb.mpfindchunk(mh_version=mps.mh_version)

    log.logmsg("loaded")
