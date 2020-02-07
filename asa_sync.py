#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# This GDB script is a wrapper on top of ret-sync/ext_gdb/sync.py
# except that we pass a context to hardcode specific information
# such as a "fake" PID and the /proc/<pid>/mappings corresponding to the 
# version we are currently debugging

import configparser
import os
import configparser
import sys

# Our own libraries
cwd = os.getcwd()
sys.path.insert(0, cwd)
from helper import *

def logmsg(s, end=None):
    if type(s) == str:
        if end != None:
            print("[asa_sync] " + s, end=end)
        else:
            print("[asa_sync] " + s)
    else:
        print(s)

# These are general mappings used by most of the firmware.
# The "x|y" entry for the lists held inside this dict have two purposes. The x
# is used to uniquely identify the associated idb that is being synced. The
# y is the corresponding binary in gdb mappings that the addresses correspond
# to for syncing with the idb
mappings_config = {
    # In 32-bit, there is no ASLR and the layout is always the same
    "32_default": [
        [0x08048000, 0x0B74ae20, 0x03702e20, "%bin_name%|lina"],
        [0xdc701000, 0xdc71e1f8, 0x1d1f8, "%bin_name%|libexpat"],
    ],

    # In 64-bit ASLR-enabled firmware, we need to have previously disabled 
    # ASLR using unpack_repack_qcow2.sh
    "64_aslr_disabled": [
        [0x555555554000, 0x55555E306940, 0x8DB2940, "%bin_name%|lina"],
        # XXX - looks like we need to comment ld to be able to debug libc.so?
        #[0x7FCA921DC000, 0x7FFFF7FFE1A8, 0x3565E221A8, "%bin_name%|ld"],
        [0x7FFFF76A5000, 0x7FFFF78CD988, 0x228988, "%bin_name%|expat"],
        [0x7ffff48f4000, 0x7FFFF4CA50B0, 0x3b10b0, "%bin_name%|libc-2.18.so"]
    ],

    # Allows us to deal with the 64-bit non ASLR-enabled firmware
    "64_noaslr": [
        [0x400000, 0x7A81158, 0x7681158, "%bin_name%|lina"]
    ],
}

# The key is determined by the path of the firmware under which lina is being
# debugged
global_mappings = {
    "asa803-k8.bin": mappings_config["32_default"],
    "asa844-k8.bin": mappings_config["32_default"],
    "asa916-k8.bin": mappings_config["32_default"],
    "asa922-4-k8.bin": mappings_config["32_default"],
    "asa923-k8.bin": mappings_config["32_default"],
    "asa924-k8.bin": mappings_config["32_default"],
    "asa924-24-k8.bin": mappings_config["32_default"],
    "asav941-200.qcow2": mappings_config["64_noaslr"],
    "asa912-smp-k8.bin": mappings_config["64_noaslr"],
    "asa924-smp-k8.bin": mappings_config["64_noaslr"],
    "asav961.qcow2": mappings_config["64_aslr_disabled"],
    "asav962-7.qcow2": mappings_config["64_aslr_disabled"],
    "asav981-5.qcow2": mappings_config["64_aslr_disabled"],
}

def patch_mapping(mappings, binname):
    # special case for firmware such as "asa924/_asa924-k8.bin"
    # where ret-sync needs the module filename to be only "asa924-k8.bin|lina"
    if "/" in binname:
        binname = binname.split("/")[1]
    out = []
    for module in mappings:
        out.append(module[:-1] + [module[-1].replace("%bin_name%", binname)])
    return out

# main() is similar to sync.py except that we pass a context to hardcode specific information
# such as a "fake" PID and the /proc/<pid>/mappings corresponding to the version we are currently
# debugging
if __name__ == "__main__":
    from helper_gdb import *
    # XXX - fix this so ret-sync can be anywhere?
    sys.path.insert(0, os.path.join(cwd, "ret-sync", "ext_gdb"))
    import sync as rs
    import importlib
    importlib.reload(rs)
    
    locations = [os.path.join(os.path.realpath(os.path.dirname(__file__)), ".sync"),
                 os.path.join(os.environ['HOME'], ".sync")]

    HOST="127.0.0.1"
    PORT=9100
    for confpath in locations:
        if os.path.exists(confpath):
            config = configparser.SafeConfigParser({'host': rs.HOST, 'port': rs.PORT})
            config.read(confpath)
            HOST = config.get("INTERFACE", 'host')
            PORT = config.getint("INTERFACE", 'port')
            logmsg("Using configuration file: %s" % (confpath))
            break
    logmsg("IDA host: %s:%s" % (HOST, PORT))

    ##### Cisco ASA specific
    bin_name = get_info()
    logmsg("firmware name: %s" % bin_name)

    try:
        mappings = global_mappings[bin_name]
        mappings = patch_mapping(mappings, bin_name)
    except KeyError:
        logmsg("ERROR: no mapping defined for %s" % bin_name)
        mappings = None
    logmsg("mappings: %s" % (mappings))

    if mappings:
        ctx = {
            # We don't have any process id while debugging Cisco ASA
            # so we hardcode it
            "pid": 200,

            # There is no mapping returned by "info proc mappings"
            # so we hardcode it
            # (gdb) info proc mappings
            # Can't determine the current process's PID: you must name one.
            "mappings": mappings
        }

        sync = rs.Sync(HOST, PORT, ctx=ctx)
    ##### end of Cisco ASA specific

        rs.Syncoff(sync)
        rs.Syncmodauto(sync)
        rs.Idblist(sync)
        rs.Idbn(sync)
        rs.Cmt(sync)
        rs.Rcmt(sync)
        rs.Fcmt(sync)
        rs.Bc(sync)
        rs.Translate(sync)
        rs.Cmd(sync)
        rs.Rln(sync)
        rs.Bbt(sync)
        rs.Bx(sync)
        rs.Cc(sync)
        rs.Patch(sync)
        rs.Help(sync)
    else:
        logmsg("No mapping defined for %s, ret-sync disabled" % bin_name)
