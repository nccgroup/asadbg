#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# This GDB script is a wrapper on top of libdlmalloc/libdlmalloc_28x.py
# or libdlmalloc/libdlmalloc_26x.py
# except that we automatically detect what ASA version we are debugging
# and pass the right mstate address if possible.

import sys
import traceback

# Our own libraries
cwd = os.getcwd()
sys.path.insert(0, cwd)
sys.path.insert(0, os.path.join(cwd, "libdlmalloc"))
import importlib
import helper_gdb as hgdb
importlib.reload(hgdb)
import helper as h
importlib.reload(h)

class logger:
    def logmsg(self, s, end=None):
        if type(s) == str:
            if end != None:
                print("[asa_libdlmalloc] " + s, end=end)
            else:
                print("[asa_libdlmalloc] " + s)
        else:
            print(s)

class dlsymbols(gdb.Command):
    help_str = "dlsymbols  : show dlmalloc symbols"

    def __init__(self):
        super(dlsymbols, self).__init__("dlsymbols", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

        self.initOK = False
        self.libdl = None
        self.target = None

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
            import libdlmalloc_28x as libdl
            self.log.logmsg("[!] Could not find heap alloc in target, defaulting to dlmalloc 2.8")
        else:
            if "dlmalloc 2.8" in self.target["heap_alloc"] or \
               "ptmalloc" in self.target["heap_alloc"]:
                import libdlmalloc_28x as libdl
                self.log.logmsg("Detected dlmalloc 2.8")
            elif "dlmalloc 2.6" in self.target["heap_alloc"]:
                import libdlmalloc_26x as libdl
                self.log.logmsg("Detected dlmalloc 2.6")
            else:
                self.log.logmsg("[!] Need to add support for new heap alloc?")
                return
        importlib.reload(libdl)
        self.libdl = libdl
        self.initOK = True

    def invoke(self, arg, from_tty):        
        if not self.initOK:
            self.log.logmsg("[!] Could not use dlsymbols")
            return

        try:
            mempool_array_addr = self.target["imagebase"] + self.target["addresses"]["mempool_array"]
        except KeyError:
            self.log.logmsg("mempool_array_addr failed to initalize, consider adding mempool_array for %s" % self.bin_name)
        else:
            if dlh.SIZE_SZ == 4:
                m = self.libdl.get_inferior().read_memory(mempool_array_addr, 4)
                mstate_addr = struct.unpack_from("<I", m, 0)[0]
            if dlh.SIZE_SZ == 8:
                m = self.libdl.get_inferior().read_memory(mempool_array_addr, 8)
                mstate_addr = struct.unpack_from("<Q", m, 0)[0]
            try:
                dl_symbols = { "mstate": mstate_addr }
                if dl_symbols != None:
                    self.log.logmsg("dl_symbols:")
                    for k in dl_symbols.keys():
                        self.log.logmsg("  %s: 0x%x" % (k, dl_symbols.get(k)))

            except Exception:
                self.log.logmsg("dl_symbols failed to initalize, consider adding target to dl_global_symbols")

if __name__ == "__main__":

    log = logger()
    dls = dlsymbols()
    help_extra = dlsymbols.help_str

    if dls.libdl:
        dlh = dls.libdl.dl_helper()
        dls.libdl.dlhelp(dlh, help_extra)
        dls.libdl.dlchunk(dlh)
        dls.libdl.dlcallback(dlh)
        dls.libdl.dlmstate(dlh)
    else:
        log.logmsg("[!] Could not initialize libdlmalloc commands")

    log.logmsg("loaded")
