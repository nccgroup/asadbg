#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# This GDB script retrieves the current thread id

try:
    import gdb
except ImportError:
    print("[curr_thread] Not running inside of GDB, exiting...")
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

def find_current_thread():
    inf = get_inferior()
    dat = gdb.execute("info threads", False, True)
    lines = dat.split("\n")
    for L in lines:
        elts = L.split()
        if elts[0] == "*":
            print("thread %s" % elts[1])
            break

print("Finding current thread...")
find_current_thread()