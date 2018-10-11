#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# IDA Python script used to rename stuff in /asa/bin/lina to be used by asadbg:
# clock_interval, lina_wind_timer, mempool_array, socks_proxy_server_start,
# aaa_admin_authenticate, mempool_list_
# Also used to get symbols in /asa/bin/lina_monitor to patch it so it can boot a
# modified /asa/bin/lina on GNS3.

import binascii
import os
import re
import string
import sys

# Note that the current way of importing an external script such as
# ida_helper.py in IDA makes it impossible to modify it and then reload the
# calling script from IDA without closing IDA and restarting it (due to some
# caching problem or Python namespaces that I don't understand yet :|)
ida_helper_path = os.path.abspath(os.path.join(sys.path[-1], "..", "idahunt"))
sys.path.insert(0, ida_helper_path)

import ida_helper
from ida_helper import *

def logmsg(s, debug=True):
    if not debug:
        return
    if type(s) == str:
        print("[asadbg_rename] " + s)
    else:
        print(s)

##################################################
###################### lina ######################
##################################################

################## rename using logging functions ##################

# The first step is to locate the "ikev2_log_exit_path" function. There are
# several ways to locate it but the simpler way is to use one of the strings
# that we know is a function name and is used when logging for this function
# ikev2_log_exit_path = my_log
# on recent 64-bit firmware with symbols, it is already defined
def rename_ikev2_log_exit_path():
    return rename_logging_function(log_funcname="ikev2_log_exit_path", funcstr_helpers=["aIkev2_parse_id"])

def rename_unicorn_log_impl():
    return rename_logging_function(log_funcname="unicorn_log_impl", funcstr_helpers=["aRemove_ns", "aRemoveNs"])

# funcstr_helpers: Looks like 1 symbol is sufficient for now
def rename_logging_function(log_funcname, funcstr_helpers):
    global ERROR_MINUS_1
    tmp = LocByName(log_funcname)
    if tmp != ERROR_MINUS_1:
        logmsg("rename_logging_function: '%s' already defined" % log_funcname)
        return True

    log_funcaddr = None
    for s in funcstr_helpers:
        addrstr = LocByName(s)
        if addrstr == ERROR_MINUS_1:
            continue

        for e in get_xrefs(addrstr):
            e = NextHead(e)
            count = 0
            # we only supports 10 instructions forwards looking for the "call <log_funcaddr>"
            # but it should be enough because the funcstr_helpers strings are passed
            # as arguments to the call
            while count <= 10:
                if GetDisasm(e).startswith("call"):
                    log_funcaddr = GetOperandValue(e, 0)
                    break
                e = NextHead(e)
                count += 1
            if log_funcaddr != None:
                break

    if log_funcaddr == None:
        logmsg("%s not found" % log_funcname)
        return False
    logmsg("Found %s = 0x%x" % (log_funcname, log_funcaddr))

    if not MakeName(log_funcaddr, log_funcname):
        logmsg("Should not happen: failed to rename to %s" % log_funcname)
        return False
    return True

# Note: description is incomplete below as now it works for ikev2_log_exit_path, unicorn_log_impl, etc.
#
# It rename functions using the ikev2_log_exit_path function and arguments passed to this function.
# Eg: for asa924-k8.bin:
#
# .text:0876F430 ikev2_add_ike_policy_by_addr proc near
# ...
# .text:0876F4B0                 mov     dword ptr [esp+10h], offset aIkev2_policy_c ; "ikev2_policy.c"
# .text:0876F4B8                 mov     dword ptr [esp+0Ch], 170h
# .text:0876F4C0                 mov     dword ptr [esp+8], offset aIkev2_add_ik_1 ; "ikev2_add_ike_policy_by_addr"
# .text:0876F4C8                 mov     dword ptr [esp+4], 4
# .text:0876F4D0                 mov     dword ptr [esp], 0
# .text:0876F4D7                 call    ikev2_log_exit_path
#
# .rodata:09EA39C2 aIkev2_add_ik_1 db 'ikev2_add_ike_policy_by_addr',0
#
# go to "0876F4D7" and executes:
# Python>get_call_arguments()
# Found argument 0: 0x0
# Found argument 1: 0x4
# Found argument 2: 0x9ea39c2
# Found argument 3: 0x170
# Found argument 4: 0x9ec093e
# {0: 0, 1: 4, 2: 166345154, 3: 368, 4: 166463806}
#
# By looking at the 3rd argument to the ikev2_log_exit_path function we get the name of the calling function
# => 0876F430 = ikev2_add_ike_policy_by_addr
def rename_using_logging_function(e=ScreenEA(), log_funcname="ikev2_log_exit_path", logfunc_arg_number=2):
    # are we a call instruction?
    mnem = GetMnem(e)
    if mnem != "call" and mnem != "jmp":
        logmsg("ERROR: not a call instruction at 0x%x" % e)
        return False

    # parse arguments, parsing instructions backwards
    args = get_call_arguments(e, count_max=35)
    if not args:
        logmsg("0x%x: get_call_arguments failed" % e)
        return False
    if len(args) < 3:
        logmsg("0x%x: Missing argument for %s" % (e, log_funcname))
        return False

    # Is the 3rd argument an offset to a string as it should be?
    # note args[0] is the first argument, args[1] the second, etc.
    seg_info = get_segments_info()
    #logmsg(args)
    #logmsg("0x%x" % e)
    if logfunc_arg_number not in args.keys():
        logmsg("Could not find argument %d in %s args" % (logfunc_arg_number, log_funcname))
        return False
    if not addr_is_in_one_segment(args[logfunc_arg_number], seg_info):
        logmsg("0x%x not a valid offset" % args[logfunc_arg_number])
        return False

    funcname = GetString(args[logfunc_arg_number])
    func = idaapi.get_func(e)
    if not func:
        logmsg("Skipping: Could not find function for %x" % e)
        return False
    current_func_addr = func.startEA
    if Name(current_func_addr).startswith("sub_"):
        #logmsg("0x%x -> %s" % (current_func_addr, funcname))
        rename_function(current_func_addr, funcname)
    else:
        pass
        #logmsg("Already named: 0x%x -> %s" % (current_func_addr, funcname))

    return True

#e.g.: my_log_addr = 0x087AADC0 # lina in asa924-k8.bin
def rename_functions_using_ikev2_log_exit_path():
    return rename_functions_using_logging_function(log_funcname="ikev2_log_exit_path", logfunc_arg_number=2)
    
# By looking at the 2nd argument of the call to unicorn_log_impl(), we get the name of the calling function
#
# XXX - add support for older firmware such as asa802-k8.bin
# as a temporary register is used and we don't support it
# .text:08AA7EDC                 mov     eax, offset aRemove_ns ; "remove_ns"
# .text:08AA7EE1                 mov     [esp+24h], ebx
# .text:08AA7EE5                 mov     [esp+20h], esi
# .text:08AA7EE9                 mov     [esp+1Ch], edx
# .text:08AA7EED                 mov     [esp+4], eax
# .text:08AA7EF1                 mov     dword ptr [esp], offset aRamfs_c ; "ramfs.c"
# .text:08AA7EF8                 call    unicorn_log_impl
def rename_functions_using_unicorn_log_impl():
    return rename_functions_using_logging_function(log_funcname="unicorn_log_impl", logfunc_arg_number=1)

def rename_functions_using_logging_function(log_funcname, logfunc_arg_number):
    global ERROR_MINUS_1
    # search for one symbol that is found using this method
    # and assume it is already done if symbol already exists
    #tmp = LocByName("ikev2_child_sa_create")
    #if tmp != ERROR_MINUS_1:
    #    logmsg("rename_functions_using_ikev2_log_exit_path: 'ikev2_child_sa_create' already defined")
    #    return True

    count = 0
    my_log_addr = LocByName(log_funcname)
    if my_log_addr == ERROR_MINUS_1:
        logmsg("ERROR: you need to find %s first. Use rename_using_logging_function() first or find it manually by using strings that look like function names such as 'ikev2_parse_packet', 'ikev2_get_sa_and_neg', etc. for IKEv2 or other for WebVPN, etc." % log_funcname)
        return False
    for e in get_xrefs(my_log_addr):
        #logmsg("0x%x" % e)
        # we don't check for return values because we better rename as many functions as possible
        # even if one failed e.g. because code was defined by not as a function.
        if rename_using_logging_function(e, log_funcname=log_funcname, logfunc_arg_number=logfunc_arg_number):
            count += 1

    logmsg("Renamed %d functions" % count)
    return True

################## timer ##################

# Eg: asa924-k8.bin
# .data:0A53F168 clock_interval dd 4C4B40h        //5000000
#
# .text:090E8C60 lina_wind_timer proc near
# .text:090E8C60
# .text:090E8C60 new             = itimerval ptr -10h
# .text:090E8C60
# .text:090E8C60                 push    ebp
# .text:090E8C61                 mov     ebp, esp
# .text:090E8C63                 sub     esp, 28h
# .text:090E8C66                 mov     ecx, clock_interval
# .text:090E8C6C                 cmp     ecx, 999999
# clock_interval = watchdog_timeout
# lina_wind_timer = set_watchdog_timer
def rename_timer_func_and_timeout():
    global ERROR_MINUS_1
    if LocByName("clock_interval") != ERROR_MINUS_1:
        logmsg("clock_interval already defined")
        return True
    watchdog_timeout = None
    set_watchdog_timer = None
    seg_info = get_segments_info()
    addr = seg_info[".data"]["startEA"]
    while addr <= seg_info[".data"]["endEA"]:
        addr = NextHead(addr)
        # Look for clock_interval. Note there should only be one of them
        if Dword(addr) == 5000000:
            break
    if addr > seg_info[".data"]["endEA"]:
        logmsg("Could not find clock_interval in .data")
        return False
    watchdog_timeout = addr
    for e in get_xrefs(addr):
        # check that next instruction is a cmp reg, 999999
        e = NextHead(e)
        if GetOperandValue(e, 1) != 999999:
            continue
        # Now go backwards to check we are at the beginning of the function
        count = 0
        func = idaapi.get_func(e)
        if not func:
            logmsg("Could not get current function for 0x%x" % e)
            return False
        #logmsg("func = 0x%x" % func.startEA)
        while count <= 5:
            e = PrevHead(e)
            #logmsg("0x%x" % e)
            if e == func.startEA:
                break
            count += 1
        if count > 5:
            continue
        set_watchdog_timer = e
        break
    if watchdog_timeout != None:
        logmsg("clock_interval = 0x%x" % watchdog_timeout)
        MyMakeName(watchdog_timeout, "clock_interval")
    if set_watchdog_timer != None:
        logmsg("lina_wind_timer = 0x%x" % set_watchdog_timer)
        MyMakeName(set_watchdog_timer, "lina_wind_timer")
    return True

################## libdlmalloc ##################

def get_mempool_array():
    global ARCHITECTURE
    funcaddr = MyLocByName("free")
    if funcaddr == None:
        return False
    bFound = False
    for e in FuncItems(funcaddr):
        disass = GetDisasm(e)
        #logmsg("%X -> %s" % (e, disass))
        # look for something like "mov     r14, ds:qword_5ACCD40[rax]" (64-bit)
        # or something like "mov     eax, ds:dword_B749C00[eax]" (32-bit)
        m = re.search("mov     \w+, ds:(.*)\[\w+\]", disass)
        if m:
            mempool_array_name = m.group(1)
            mempool_array = MyLocByName(mempool_array_name)
            if mempool_array == None:
                logmsg("bad mempool_array_name, should not happen")
                return False
            bFound = True
            break
    if not bFound:
        logmsg("[x] mempool_array not found")
        return False
    MyMakeName(mempool_array, "mempool_array")
    logmsg("mempool_array = 0x%x" % mempool_array)
    return True

################## libmempool ##################

def get_mempool_list_():
    seg_info = get_segments_info()
    global ARCHITECTURE
    global ERROR_MINUS_1
    if LocByName("mempool_list_") != ERROR_MINUS_1:
        logmsg("mempool_list_ already defined")
        return True

    if rename_function_by_aString_being_used("aMalloc_show_to", "malloc_show_top_usage") != True:
        logmsg("failed to rename malloc_show_top_usage so can't find mempool_list_")
        return False
    funcaddr = MyLocByName("malloc_show_top_usage")
    if funcaddr == None:
        logmsg("can't find malloc_show_top_usage. Should not happen")
        return False

    count = 0
    for e in FuncItems(funcaddr):
        # asa-smp 64-bit and asa 32-bit
        if GetOpType(e, 0) == o_reg and GetOpType(e, 1) == o_imm and \
            GetOperandValue(e, 1) >= seg_info[".data"]["startEA"] and \
            GetOperandValue(e, 1) <= seg_info[".data"]["endEA"]:
                mempool_list_ = GetOperandValue(e, 1)
                val = Dword(mempool_list_)
                if val >= 0x100:
                    logmsg("skipping mempool_list_ = 0x%x as wrong value in there: %d" % (mempool_list_, val))
                    count += 1
                    continue
                MyMakeName(mempool_list_, "mempool_list_")
                logmsg("mempool_list_ = 0x%x" % mempool_list_)
                break
        # asav 64-bit
        elif GetOpType(e, 0) == o_reg and GetOpType(e, 1) == o_mem and \
            GetOperandValue(e, 1) >= seg_info[".got"]["startEA"] and \
            GetOperandValue(e, 1) <= seg_info[".got"]["endEA"]:
                mempool_list__ptr = GetOperandValue(e, 1)
                mempool_list_ = Qword(mempool_list__ptr)
                val = Dword(mempool_list_)
                if val >= 0x100:
                    logmsg("skipping mempool_list__ptr = 0x%x and mempool_list_ = 0x%x as wrong value in there: %d" % (mempool_list__ptr, mempool_list_, val))
                    count += 1
                    continue
                MyMakeName(mempool_list__ptr, "mempool_list__ptr")
                MyMakeName(mempool_list_, "mempool_list_")
                logmsg("mempool_list__ptr = 0x%x" % mempool_list__ptr)
                logmsg("mempool_list_ = 0x%x" % mempool_list_)
                break
        if count >= 20:
            logmsg("cound not find mempool_list__ptr/mempool_list_ after 20 instructions")
            break
        count += 1



################## debug shell ##################

# rodata:0A55698D aVnetProxyMainT db 'vnet-proxy main thread',0
# ...
# .text:090ACE90 sub_090ACE90
# ...
# .text:090ACF7D                 mov     dword ptr [esp], offset aVnetProxyMainT ; "vnet-proxy main thread"
# => sub_090ACE90 == socks_proxy_server_start
def rename_socks_proxy_server_start():
    return rename_function_by_aString_being_used("aVnetProxyMainT", "socks_proxy_server_start", xref_func=MyLastXrefTo)

# All aSYouDoNotHaveA xrefs points to process_create so we take the first one
#
# 9.2.4:
# .rodata:09CF5060 aSYouDoNotHaveA db 0Ah
# .rodata:09CF5060                 db '[ %s ] You do NOT have Admin Rights to the console !',0Ah,0
# => xref gives us:
# .text:08085B00 aaa_admin_authenticate     proc near
# ...
# .text:08086004 mov dword ptr [esp], offset aSYouDoNotHaveA ; "\n[ %s ] You do NOT have Admin Rights t"...
def rename_aaa_admin_authenticate():
    return rename_function_by_aString_being_used("aSYouDoNotHaveA", "aaa_admin_authenticate")

def main_lina():
    # logging
    res = rename_ikev2_log_exit_path()
    if not res:
        logmsg("rename_ikev2_log_exit_path() failed")
        # we continue for the extra functions but
        # rename_functions_using_ikev2_log_exit_path() will fail of course
    res = rename_functions_using_ikev2_log_exit_path()
    if not res:
        logmsg("rename_functions_using_ikev2_log_exit_path() failed")
    res = rename_unicorn_log_impl()
    if not res:
        logmsg("rename_unicorn_log_impl() failed")
    res = rename_functions_using_unicorn_log_impl()
    if not res:
        logmsg("rename_functions_using_unicorn_log_impl() failed")

    # timer
    rename_timer_func_and_timeout()

    # libdlmalloc
    get_mempool_array()
    get_mempool_list_()

    # debug shell
    rename_socks_proxy_server_start()
    rename_aaa_admin_authenticate()

##################################################
################## lina_monitor ##################
##################################################

# .rodata:0000000000019D00 aCode_sign_veri db 'code_sign_verify_signature_image',0
# ...
# .text:0000000000005690 sub_5690        proc near
# ...
#.text:00000000000057E6                 lea     rsi, aCode_sign_veri ; "code_sign_verify_signature_image"
#.text:00000000000057ED                 lea     rdi, aS_NotAnElfImag ; "%s. Not an ELF image"
# => sub_5690 == code_sign_verify_signature_image
def find_lina_signature_check():
    res = rename_function_by_aString_being_used(
                "aCode_sign_veri",
                "code_sign_verify_signature_image",
                xref_func=MyFirstXrefTo)
    if not res:
        res = rename_function_by_aString_being_used(
                "aCodeSignVerify",
                "code_sign_verify_signature_image",
                xref_func=MyFirstXrefTo)

    if not res:
        logmsg("Failed to find code_sign_verify_signature_image()")
        return

    # Now check we find a "jz" a few instructions after
    # "call code_sign_verify_signature_image"
    addr = MyLocByName("code_sign_verify_signature_image")
    if not addr:
        logmsg("Could not find code_sign_verify_signature_image")
        return False

    for xref in get_xrefs(addr):
        addr = xref
        # it is usually the third instruction after the call:
        # .text:000000000000395B E8 30 1D 00+   call    code_sign_verify_signature_image
        # .text:0000000000003960 85 C0          test    eax, eax
        # .text:0000000000003962 89 C3          mov     ebx, eax
        # .text:0000000000003964 74 50          jz      short loc_39B6
        count = 0
        e = addr
        bFound = False
        # XXX - instead of counting to 4, we could just find the basic block  
        # and test the instruction at block.endEA?
        while count <= 4:
            e = NextHead(e)
            print(GetDisasm(e))
            if GetDisasm(e).startswith("jz"):
                MyMakeName(e, "jz_after_code_sign_verify_signature_image")
                logmsg("jz_after_code_sign_verify_signature_image = 0x%x" % e)
                bFound = True
                break
            count += 1

    if not bFound:
        logmsg("Failed to find jz instruction for jz_after_code_sign_verify_signature_image ")

    return bFound

def main_lina_monitor():
    find_lina_signature_check()

##################################################
###################### libc ######################
##################################################

def main_libc():
    # We currently only rely on __libc_free, which is exported
    pass

##################################################
###################### main ######################
##################################################

if __name__ == '__main__':
    if ida_helper.get_idb_name() == "lina":
        logmsg("Analyzing lina...")
        main_lina()
    elif ida_helper.get_idb_name() == "lina_monitor":
        logmsg("Analyzing lina_monitor...")
        main_lina_monitor()
    elif ida_helper.get_idb_name() == "libc.so":
        logmsg("Analyzing libc...")
        main_libc()
    else:
        logmsg("ERROR: Unsupported filename")

    # Note that this script is called automatically from the command line
    # Consequently, we cannot call sys.exit(), otherwise the temporary files
    # (.id0, .id1, etc.) will not packed and nothing is saved into the .idb.
    # This allows us to cleanly exit IDA upon completion
    if "DO_EXIT" in os.environ:
        Exit(1)
