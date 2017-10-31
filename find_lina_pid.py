#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# This GDB script bruteforces PIDs and execute some GDB commands 
# in order to find the lina PID

try:
    import gdb
except ImportError:
    print("[find_lina_pid] Not running inside of GDB, exiting...")
    exit()

import sys

def get_inferior():
    try:
        if len(gdb.inferiors()) == 0:
            print("No gdb inferior could be found.")
            return -1
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        print("This gdb's python support is too old.")
        exit()

def find_lina_pid():
    inf = get_inferior()
    pid = 0
    found = 0
    maxpids = 0x300 # usually lina is around 500-530
    while pid < maxpids:
        #print("%d" % pid)
        pid += 1
        dat = gdb.execute("info proc cmdline %d" % pid, False, True)
        #if "unable to open" not in dat:
        #    print(dat)
        found = dat.find("lina'")
        if found != -1:
            idx1 = len("process ")
            idx2 = dat.find("\n")
            pid = dat[idx1:idx2]
            print("%d" % int(pid))
            break

print("Finding lina PID:")
find_lina_pid()
print("You can use the following to see the lina mapping: info proc mappings <pid>")