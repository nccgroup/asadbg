#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# This GDB script allows to ignore errors when executing other commands
# Usage: ignore-errors <command>
#        E.g. ignore-errors sync
#
# From https://sourceware.org/ml/gdb/2010-06/msg00100.html

class IgnoreErrorsCommand (gdb.Command):
    """Execute a single command, ignoring all errors.
       Only one-line commands are supported.
       This is primarily useful in scripts."""

    def __init__ (self):
        super (IgnoreErrorsCommand, self).__init__ ("ignore-errors",
                                                    gdb.COMMAND_OBSCURE,
                                                    # FIXME...
                                                    gdb.COMPLETE_COMMAND)

    def invoke (self, arg, from_tty):
        try:
            gdb.execute (arg, from_tty)
        except:
            pass

IgnoreErrorsCommand ()
