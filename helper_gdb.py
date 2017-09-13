#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# This contains helpers for other parts. Note that some of them are common
# to several projects: libdlmalloc, libptmalloc, libmempool, etc.

import os, re, json, pickle, gdb
import helper as h
import importlib
importlib.reload(h)

def logmsg(s, debug=True):
    if not debug:
        return
    if type(s) == str:
        print("[helper_gdb] " + s)
    else:
        print(s)

def get_info():
    res = gdb.execute("maintenance info sections ?", to_string=True)
    bin_name = os.path.basename(h.build_bin_name(res))
    if not bin_name:
        raise("get_info: failed to find bin name")
    return bin_name
