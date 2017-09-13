#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# IDA Python script used to save addresses in /asa/bin/lina into an external
# database to be used by asadbg.
#
# Assume you previously used asadbg_rename.py.

import argparse
import json
import re
import sys
import os

import filelock
from helper import *
    
# Note that the current way of importing an external script such as
# ida_helper.py in IDA makes it impossible to modify it and then reload the
# calling script from IDA without closing IDA and restarting it (due to some
# caching problem or Python namespaces that I don't understand yet :|)
from ida_helper import *

def logmsg(s, debug=True):
    if not debug:
        return
    if type(s) == str:
        print("[asadbg_hunt] " + s)
    else:
        print(s)

# merge = if you want to merge results in existing ones
#         such as adding symbols to existing elements
# replace = useful if we want to remove old names before adding real symbols
def hunt(symbols, dbname, merge=True, replace=False):
    
    # parse version/fw from directory name
    idbdir = GetIdbDir()
    version = build_version(idbdir)
    if not version:
        logmsg("Can't parse version in %s" % idbdir)
        sys.exit()
    fw = build_bin_name(idbdir)
    if not fw:
        logmsg("Can't parse fw in %s" % idbdir)
        sys.exit()

    new_target = {}
    new_target["fw"] = fw
    new_target["arch"] = ARCHITECTURE
    # by default we don't know the imagebase so we will save
    # absolute addresses in new_target["addresses"]
    new_target["imagebase"] = 0
    # XXX - add fw md5 to db?

    prevtime = time.time()
    lock = filelock.FileLock("asadb.json")
    with lock.acquire():
        newtime = time.time()
        logmsg("Acquired lock after %d seconds" % int(newtime-prevtime))

        # load old targets
        targets = []
        if os.path.isfile(dbname):
            with open(dbname, "rb") as tmp:
                logmsg("Reading from %s" % dbname)
                targets = json.loads(tmp.read())
        else:
            logmsg("Creating new db: %s" % dbname)
        #logmsg("Existing targets:")
        #logmsg(targets)

        # Building new entry
        new_target["version"] = version
        addresses = {}
        for s,func in symbols.items():
            if not s:
                continue
            name = s
            if name.startswith("instruction_"):
                name = s[len("instruction_"):]
            # addr can actually be an address but also an offset we need 
            # (e.g. tls->default_channel)...
            logmsg("Looking up %s" % s)
            addr = func(s)
            # we check both as we never want to add a -1 symbol and sometimes
            # the architecture detected is wrong and we ended up saving -1 :|
            if addr == 0xffffffffffffffff or addr == 0xffffffff or addr == None:
                logmsg("[x] Impossible to get '%s' symbol" % name)
                continue
            #logmsg("%s = 0x%x (%s)" % (name, addr, type(addr)))
            addresses[name] = addr
        #logmsg(addresses)
        new_target['addresses'] = addresses

        if is_new(targets, new_target):
            logmsg("New target: %s (%s)" % (version, fw))
            logmsg(addresses)
            targets.append(new_target)
        elif merge == True:
            logmsg("Merging target: %s (%s)" % (version, fw))
            i = merge_target(new_target, targets)
            print(targets[i])
        elif replace == True:
            logmsg("Replacing target: %s (%s)" % (version, fw))
            replace_target(new_target, targets)
            logmsg(new_target)
        else:
            logmsg("Skipping target in pickle: %s (%s)" % (version, fw))
        # sort targets by version. Drawback: index changes each time we add
        # a new firmware but it should not anymore once we have them all
        targets = sorted(targets, key=lambda k: map(int, k["version"].split(".")))

        logmsg("Writing to %s" % dbname)
        open(dbname, "wb").write(json.dumps(targets, indent=4))
        
if __name__ == '__main__':

    try:
        # e.g. /path/to/asadbg/asadb.json
        dbname = os.environ["ASADBG_DB"]
    except:
        logmsg("You need to define ASADBG_DB first")
        sys.exit()

    symbols = {
        "clock_interval":LocByName, 
        "mempool_array":LocByName, 
        "mempool_list_":LocByName, 
        "socks_proxy_server_start":LocByName,
        "aaa_admin_authenticate":LocByName,
        "mempool_list_":LocByName,
    }
    symbols32 = {}
    symbols64 = {}
    if ARCHITECTURE == 32:
        symbols.update(symbols32)
    elif ARCHITECTURE == 64:
        symbols.update(symbols64)
    else:
        logmsg("Invalid architecture")
        sys.exit()

    hunt(symbols, dbname)

    # This allows us to cleanly exit IDA upon completion
    if "DO_EXIT" in os.environ:
        Exit(1)
