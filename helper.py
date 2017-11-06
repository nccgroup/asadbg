#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# This contains helpers for other parts. Note that some of them are common
# to several projects: asadbg, asafw, libdlmalloc, libptmalloc, libmempool, etc.

import os
import re
import sys
import json, time
import pickle
import traceback

class logger:
    def logmsg(s, debug=True):
        if not debug:
            return
        if type(s) == str:
            print("[helper_gdb] " + s)
        else:
            print(s)

# Taken from gef. Let's us see proper backtraces from python exceptions
def show_last_exception():
    PYTHON_MAJOR = sys.version_info[0]
    horizontal_line = "-"
    right_arrow = "->"
    down_arrow = "\\->"

    print("")
    exc_type, exc_value, exc_traceback = sys.exc_info()
    print(" Exception raised ".center(80, horizontal_line))
    print("{}: {}".format(exc_type.__name__, exc_value))
    print(" Detailed stacktrace ".center(80, horizontal_line))
    for fs in traceback.extract_tb(exc_traceback)[::-1]:
        if PYTHON_MAJOR==2:
            filename, lineno, method, code = fs
        else:
            try:
                filename, lineno, method, code = fs.filename, fs.lineno, fs.name, fs.line
            except:
                filename, lineno, method, code = fs

        print("""{} File "{}", line {:d}, in {}()""".format(down_arrow, filename,
                                                            lineno, method))
        print("   {}    {}".format(right_arrow, code))


# An example of what this function is doing: 
#
# If you had two IDBs associated with asa924-smp-k8.bin, but one was from
# hardware and one was from a qcow (and thus asav), then you could have folders
# like this:
#
# ~/asa924-smp-k8.bin/asa924-smp-k8.idb
# ~/asav924-smp-k8.bin/asa924-smp-k8.idb
#
# This way the direct parent folder name itself is used as the identifier. This
# identifier is path is also used to look up target info inside of the
# mapping_config dictionary in ext_gdb/sync.py. The general problem with this
# is if the filesystem hosting the idb is not the same as the one hosting the
# files, as the directory layout might be totally different.
def build_bin_name(s):
    log = logger()
    if "asav" in s:
        match = re.search(r'asav([^\\/.]+)\.qcow2', s)
        if not match:
            log.logmsg("Could not find the asavXXX.qcow2 in string: %s" % s)
            return ''
        return "asav%s.qcow2" % match.group(1)
    elif "SPA" in s:
        match = re.search(r'asa([^\\/.]+)\.SPA', s)
        if not match:
            log.logmsg("Could not find the asaXXX.SPA in string: %s" % s)
            return ''
        return "asa%s.SPA" % match.group(1)
    else:
        match = re.search(r'asa([^\\/.]+)\.bin', s)
        if not match:
            log.logmsg("Could not find the asaXXX.bin in string: %s" % s)
            return ''
        return "asa%s.bin" % match.group(1)

# parse the version from the firmware name
# examples: asa811-smp-k8.bin, asa825-k8.bin, asa805-31-k8.bin
# XXX - most of this is a copy of the above, so shouldn't duplicate
def build_version(dirname):

    log = logger()
    version = ''
    if "asav" in dirname:
        match = re.search(r'asav([^\\/.]+)\.qcow2', dirname)
        if not match:
            log.logmsg("Could not find the asavXXX.qcow2 in string: %s" % dirname)
            return ''
    elif "SPA" in dirname:
        match = re.search(r'asa([^\\/.]+)\.SPA', dirname)
        if not match:
            log.logmsg("Could not find the asaXXX.SPA in string: %s" % dirname)
            return ''
    else:
        match = re.search(r'asa([^\\/.]+)\.bin', dirname)
        if not match:
            log.logmsg("Could not find the asaXXX.bin in string: %s" % dirname)
            return ''

    verName = match.group(1)
    elts = verName.split("-")
    first = True
    try:
        for e in elts:
            if first:
                for c in e:
                    if not first:
                        version += '.'
                    version += '%c' % c
                    first = False
            else:
                version += '.%d' % int(e)
    # assume we get one at some point (eg: "k8") - it means we are done for now
    except ValueError:
        pass

    return version

def is_new(targets, new):
    for t in targets:
        if t["version"] == new["version"] and t["fw"] == new["fw"]:
            return False
    return True

def replace_target(new_target, targets):
    for i in range(len(targets)):
        t = targets[i]
        if t["version"] != new_target["version"] or t["fw"] != new_target["fw"]:
            continue
        # found previous target, let's replace it
        targets[i] = new_target
        break

def merge_target(new_target, targets, executable_name="lina"):
    log = logger()
    if executable_name == "lina":
        base_name = "lina_imagebase"
        addr_name = "addresses"
    elif executable_name == "lina_monitor":
        base_name = "lm_imagebase"
        addr_name = "lm_addresses"
    else:
        log.logmsg("ERROR: bad elf name in merge_target()")
        return None
    for i in range(len(targets)):
        t = targets[i]
        if t["version"] != new_target["version"] or t["fw"] != new_target["fw"]:
            continue
        # found previous target, let's merge it
        for name, addr in new_target[addr_name].items():
            if addr_name not in t.keys():
                t[addr_name] = {}
            if base_name not in t.keys():
                t[base_name] = 0
            # these keys come from info.py import
            if base_name in t.keys() and "ASLR" in t.keys():
                    # special case for offset, not an address
                if name.startswith("OFFSET_") or name.startswith("REG_"):
                    t[addr_name][name] = addr

                elif t["ASLR"] == True:
                    # we assume imagebase has been set correctly to either 0
                    # or the value it has when ASLR is disabled for this fw
                    # as what asafw does :)
                    t[addr_name][name] = addr
                else:
                    t[addr_name][name] = addr - t[base_name]
            else:
                t[addr_name][name] = addr
        targets[i] = t
        break
    return i

def load_targets(targetdb):
    # XXX log.logmsg() does not work 
    # as it prints <helper.logger instance at 0x06B77EB8>
    # so we use print() instead :|
    print("[helper] Reading from %s" % targetdb)
    if targetdb.endswith(".pickle"):
        usePickle = True
    elif targetdb.endswith(".json"):
        usePickle = False
    else:
        print("[helper] Can't decide if pickle to use based on extension")
        sys.exit()
    if os.path.isfile(targetdb):
        if usePickle:
            # old format
            try:
                targets = pickle.load(open(targetdb, "rb"))
            # ValueError: insecure string pickle
            # long story short, while using git on both Linux/Windows, do NOT ask git to replace
            # CRLF with its own between the local version and the remote server. Indeed, the pickle will
            # be modified and it will be treated in a text file instead of binary :/
            except ValueError:
                # hax so we can use it if it fails to open the db
                targets = pickle.load(open(targetdb, "r"))
        else:
            # even when using filelock, it looks like sometimes we read bad JSON
            # so we try several times :|
            max_attempts = 5
            attempts = 0
            while attempts < max_attempts:
                try:
                    with open(targetdb, "r") as tmp:
                        targets = json.loads(tmp.read())
                except ValueError:
                    print("[helper] Failed to read valid JSON, trying again in 1 sec")
                    time.sleep(1)
                    attempts += 1
                else:
                    break
            if attempts == max_attempts:
                print('[helper] [!] failed to read %s' % targetdb)
                sys.exit() 
    else:
        print('[helper] [!] %s file not found' % targetdb)
        sys.exit() 
    return targets 
