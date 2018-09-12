#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# IDA Python script used to save addresses in /asa/bin/lina into an external
# database to be used by asadbg. Also for /asa/bin/lina_monitor.
#
# Assume you previously used asadbg_rename.py.

import argparse
import filelock
import json
import os
import re
import sys
import time

# ida
import idc
import idautils

# asadbg imports
import helper
#from helper import *
# Note that the current way of importing an external script such as
# ida_helper.py in IDA makes it impossible to modify it and then reload the
# calling script from IDA without closing IDA and restarting it (due to some
# caching problem or Python namespaces that I don't understand yet :|)
ida_helper_path = os.path.abspath(os.path.join(sys.path[-1], "..", "idahunt"))
sys.path.insert(0, ida_helper_path)
import ida_helper

#from ida_helper import *

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
def hunt(symbols, dbname, merge=True, replace=False, bin_name="lina"):
    if bin_name == "lina":
        base_name = "lina_imagebase"
        addr_name = "addresses"
    elif bin_name == "lina_monitor":
        base_name = "lm_imagebase"
        addr_name = "lm_addresses"
    elif bin_name == "libc.so":
        base_name = "libc_imagebase"
        addr_name = "libc_addresses"
    else:
        logmsg("ERROR: bad elf name in hunt()")
        return None

    # parse version/fw from directory name
    idbdir = idautils.GetIdbDir()
    version = helper.build_version(idbdir)
    if not version:
        logmsg("Can't parse version in %s" % idbdir)
        sys.exit()
    fw = helper.build_bin_name(idbdir)
    if not fw:
        logmsg("Can't parse fw in %s" % idbdir)
        sys.exit()

    new_target = {}
    new_target["fw"] = fw
    new_target["arch"] = ida_helper.ARCHITECTURE
    # by default we don't know the imagebase so we will save
    # absolute addresses in new_target[addr_name]
    new_target[base_name] = 0
    # XXX - add fw md5 to db?

    prevtime = time.time()
    lock = filelock.FileLock("asadb_json")
    with lock.acquire():
        newtime = time.time()
        logmsg("Acquired lock after %d seconds" % int(newtime-prevtime))

        # load old targets
        targets = []
        if os.path.isfile(dbname):
            targets = helper.load_targets(dbname)
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
        new_target[addr_name] = addresses

        if helper.is_new(targets, new_target):
            logmsg("New target: %s (%s)" % (version, fw))
            logmsg(addresses)
            targets.append(new_target)
        elif merge == True:
            logmsg("Merging target: %s (%s)" % (version, fw))
            i = helper.merge_target(new_target, targets, bin_name=bin_name)
            if i != None:
                print(json.dumps(targets[i], indent=2))
#               print(targets[i])
            else:
                logmsg("Skipping target: %s (%s) as helper.merge_target() failed" % (version, fw))
        elif replace == True:
            logmsg("Replacing target: %s (%s)" % (version, fw))
            helper.replace_target(new_target, targets)
            logmsg(new_target)
        else:
            logmsg("Skipping target: %s (%s)" % (version, fw))
        # sort targets by version. Drawback: index changes each time we add
        # a new firmware but it should not anymore once we have them all
        targets = sorted(targets, key=lambda k: map(int, k["version"].split(".")))

        logmsg("Writing to %s" % dbname)
        open(dbname, "wb").write(json.dumps(targets, indent=4))


def main_lina(dbname):
    symbols = {
        "clock_interval":idc.LocByName, 
        "mempool_array":idc.LocByName, 
        "mempool_list_":idc.LocByName, 
        "socks_proxy_server_start":idc.LocByName,
        "aaa_admin_authenticate":idc.LocByName,
        "mempool_list_":idc.LocByName,
    }
    symbols32 = {}
    symbols64 = {}
    if ida_helper.ARCHITECTURE == 32:
        symbols.update(symbols32)
    elif ida_helper.ARCHITECTURE == 64:
        symbols.update(symbols64)
    else:
        logmsg("Invalid architecture")
        sys.exit()

    hunt(symbols, dbname, bin_name="lina")

def main_lina_monitor(dbname):
    symbols = {
        "jz_after_code_sign_verify_signature_image":idc.LocByName,
    }
    if ida_helper.ARCHITECTURE == 32:
        logmsg("WARNING: not supported/tested yet")
    elif ida_helper.ARCHITECTURE == 64:
        pass
    else:
        logmsg("Invalid architecture")
        sys.exit()

    hunt(symbols, dbname, bin_name="lina_monitor")

def main_libc(dbname):
    symbols = {
        "free":ida_helper.MyLocByName,
    }
    if ida_helper.ARCHITECTURE == 32:
        logmsg("WARNING: not supported/tested yet")
    elif ida_helper.ARCHITECTURE == 64:
        pass
    else:
        logmsg("Invalid architecture")
        sys.exit()

    hunt(symbols, dbname, bin_name="libc.so")

def main():
    try:
        # e.g. /path/to/asadbg/asadb.json
        dbname = os.environ["ASADBG_DB"]
    except:
        logmsg("You need to define ASADBG_DB first")
        sys.exit()

    if ida_helper.get_idb_name() == "lina":
        logmsg("Hunting lina...")
        main_lina(dbname)
    elif ida_helper.get_idb_name() == "lina_monitor":
        logmsg("Hunting lina_monitor...")
        main_lina_monitor(dbname)
    elif ida_helper.get_idb_name() == "libc.so":
        logmsg("Hunting libc...")
        main_libc(dbname)
    else:
        logmsg("ERROR: Unsupported filename")

    # This allows us to cleanly exit IDA upon completion
    if "DO_EXIT" in os.environ:
        # XXX - Was Exit(1)
        idc.qexit(1)

if __name__ == '__main__':
    main()
