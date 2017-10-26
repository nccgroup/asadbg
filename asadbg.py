#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Entry point for the Cisco ASA debugger. Heavily tested on Linux.
# Supports real ASA 32-bit, 64-bit as well as GNS3 emulator.
#
# When used for debugging, it automatically executes the commands to enable
# gdb during boot, and starts a gdb client with the right gdbinit.
#
# Notes:
# - You can use this script before unplugging/replugging a real ASA power socket
#   as it will just read the serial line until it detects the boot sequence.

import serial, sys, time, binascii, os, argparse
import platform, pprint, json, getpass, inspect, configparser

# Our own libraries
import comm

def logmsg(s, end=None):
    if type(s) == str:
        if end != None:
            print("[asadbg] " + s, end=end)
        else:
            print("[asadbg] " + s)
    else:
        print(s)

def get_target(asadb_file, version, arch):
    if not os.path.isfile(asadb_file):
        logmsg("Error: You must have a valid db file: %s doesn't exist" % asadb_file)
        sys.exit()
    with open(asadb_file, "r") as tmp:
        targets = json.loads(tmp.read())
    for t in targets:
        if t["version"].replace(".", "") == version:
            if arch == "64" and t["arch"] == 64:
                return t
            elif arch == "gns3" and "asav" in t["fw"]:
                return t
            elif arch == "32" and t["arch"] == 32:
                return t
            else:
                return t
    return None

def start_shell(port, doLog=False):
    input("\n[asadbg] Hit any key to start shell using 'screen %s'" % port)
    if doLog:
        os.system("screen -L %s" % port)
    else:
        os.system("screen %s" % port)

# XXX - The warning is redundant for build_gdbinit
def is_debugging_path_ok(version, rootfs_path, asadb_file, arch):
    logmsg("Using architecture: %s" % arch)
    target = get_target(asadb_file, version, arch)
    if not target:
        logmsg("Warning: Version not supported yet in db file")
    linafile = os.path.join(rootfs_path, 'asa/bin/lina')
    logmsg("Trying lina: %s" % linafile)

    return os.path.isfile(linafile)

def build_gdbinit(rootfs_path, targetdb, gdbinit, remote_ip, remote_port, serial_port, version, gdbinitfile=None, arch=None, scripts=None, use_retsync=False, cont=False, find_lina=False, use_display=False, debug=False):
    target = get_target(targetdb, version, arch=arch)
    if debug:
        logmsg("Using target:")
        pprint.pprint(target)
    if not target:
        logmsg("Warning: Version not supported yet in db file")

    if gdbinitfile == None:
        gdbinitfile = 'gdbinit_%s' % version

    linafile = os.path.join(rootfs_path, 'asa/bin/lina')
    searchbin = os.path.join(rootfs_path, 'bin')
    searchlib = os.path.join(rootfs_path, 'lib')
    symlinafile = os.path.join(rootfs_path, '/asa/bin/lina%s_sym' % version)

    gdbinit = gdbinit.replace('%VERSION%', version)
    gdbinit = gdbinit.replace('%LINA%', linafile)
    gdbinit = gdbinit.replace('%PREFIX%', rootfs_path)
    gdbinit = gdbinit.replace('%SEARCHBIN%', searchbin)
    gdbinit = gdbinit.replace('%SEARCHLIB%', searchlib)
    gdbinit = gdbinit.replace('%SYMLINA%', symlinafile)
    gdbinit = gdbinit.replace("%DEVTTY%", serial_port)
    gdbinit = gdbinit.replace("%REMOTE_IP%", remote_ip)
    gdbinit = gdbinit.replace("%REMOTE_PORT%", remote_port)

    if find_lina:
        gdbinit = gdbinit.replace('%FINDLINAPID%', "1")
    else:
        gdbinit = gdbinit.replace('%FINDLINAPID%', "0")

    if target:
        # XXX - Redundant in light of us passing arch anyway? 
        if target["arch"] == 32:
            gdbinit = gdbinit.replace('%ARCH32%', "1")
            gdbinit = gdbinit.replace('%ARCH64%', "0")
        elif target["arch"] == 64:
            gdbinit = gdbinit.replace('%ARCH32%', "0")
            gdbinit = gdbinit.replace('%ARCH64%', "1")
        else:
            logmsg("Error: Invalid architecture, should not happen")
            sys.exit()
    else:
        if arch == "32":
            gdbinit = gdbinit.replace('%ARCH32%', "1")
            gdbinit = gdbinit.replace('%ARCH64%', "0")
        elif arch == "64":
            gdbinit = gdbinit.replace('%ARCH32%', "0")
            gdbinit = gdbinit.replace('%ARCH64%', "1")

    if arch == "gns3":
        gdbinit = gdbinit.replace('%TCPIP%', "1")
        gdbinit = gdbinit.replace('%SERIAL%', "0")
        if not target:
            logmsg("Warning: Assuming 64-bit due to GNS3 arch and no target file")
            gdbinit = gdbinit.replace('%ARCH32%', "0")
            gdbinit = gdbinit.replace('%ARCH64%', "1")
    else:
        gdbinit = gdbinit.replace('%TCPIP%', "0")
        gdbinit = gdbinit.replace('%SERIAL%', "1")

    if use_retsync:
        gdbinit = gdbinit.replace('%RETSYNC%', "1")
    else:
        gdbinit = gdbinit.replace('%RETSYNC%', "0")
    if use_display:
        gdbinit = gdbinit.replace('%DISPLAY%', "1")
    else:
        gdbinit = gdbinit.replace('%DISPLAY%', "0")

    ss = ""
    if scripts:
        for s in scripts:
            ss += "source %s\n" % s
    gdbinit = gdbinit.replace('%SCRIPTS%', ss[:-1])

    if cont == True:
        gdbinit = gdbinit.replace('%CONTINUE%', "1")
    else:
        gdbinit = gdbinit.replace('%CONTINUE%', "0")

    if target:
        gdbinit = gdbinit.replace('%WATCHDOG_TIMEOUT_ADDR%', \
                                      "0x%08x" % (target['imagebase'] + target['addresses']['clock_interval']))
    else:
        gdbinit = gdbinit.replace('set *%WATCHDOG_TIMEOUT_ADDR%', "#set *%WATCHDOG_TIMEOUT_ADDR%")
        gdbinit = gdbinit.replace("Watchdog disabled", "Watchdog not disabled due to missing asadb file")

    open(gdbinitfile, 'wb').write(bytes(gdbinit, encoding="UTF8"))

    return gdbinitfile

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--name', dest='name', default=None, 
                        help='Name for an entry in a asadbg.cfg config file')
    parser.add_argument('--version', dest='version', default=None,
                        help='Router version (eg: 932200, 961, etc.)')
    parser.add_argument('--arch', dest='arch', default=None,
                        help='Architecture {32, 64, gns3}')
    parser.add_argument('--rootfs-path', dest='rootfs_path', default=None,
                        help='Path to the extracted rootfs (debugging only)')
    parser.add_argument('--firmware-type', dest='firmware_type', default=None,
                        help='Firmware type {normal, rooted, gdb}')
    parser.add_argument('--attach-gdb', dest='attach_gdb', action='store_true',
                        help='Attach to gdbserver at startup')
    parser.add_argument('--firmware', dest='firmware', default=None,
                        help='Firmware filename to boot (REAL ASA only and MUST already be on the flash)')
    parser.add_argument('--config', dest='config', default=None,
                        help='Config filename to use (REAL ASA only and MUST already be on the flash)')
    parser.add_argument('--gns3-host', dest='gns3_host', default=None, 
                        help='IP for emulator instance (GNS3 only)')
    parser.add_argument('--gns3-port', dest='gns3_port', default=None, help='Serial port (REAL ASA only)')
    parser.add_argument('--serial-port', dest='serial_port', default=None, help='TCP port for emulator instance (GNS3 only)')
    parser.add_argument('--asadb-file', dest='asadb_file', default=None, 
                        help='Database for targets (e.g. asadb.json)')

    parser.add_argument('--ret-sync', dest='ret_sync', default=False, action="store_true",
                        help='Load ret-sync (debugging only)')
    parser.add_argument('--display', dest='display', default=False, action="store_true",
                        help='Use "display" command in GDB to show instructions pointed by $pc')
    parser.add_argument('--scripts', dest='scripts', nargs="+",
                        help='List of GDB scripts to execute (debugging only)')
    parser.add_argument('--continue', dest='continue_exec', default=False, action="store_true",
                        help='Continue in GDB (normally pauses to allow setting additional bps)')
    parser.add_argument('--find-lina', dest='find_lina', default=False, action="store_true",
                        help='Try to find lina PID')
    parser.add_argument('--reboot', dest='reboot', action='store_true',
                        help='Reboot the router manually before loading new version (REAL ASA only)')
    parser.add_argument('--dolog', dest='dolog', default=False, action="store_true",
                        help='Enable logging for screen in case of no gdb attached')
    parser.add_argument('--asadbg-config', dest='asadbg_config', default=None,
                        help='Alternative path for an asadbg.cfg')
    args = parser.parse_args()
    
    name = args.name
    version = None
    arch = None
    rootfs_path = None
    firmware_type = None
    attach_gdb = False
    firmware = None
    config = None # Use "startup-config" by default
    gns3_host = "localhost"
    gns3_port = "8000"
    serial_port = "/dev/ttyUSB0"
    asadb_file = None
    ret_sync = args.ret_sync
    display = args.display
    scripts = []
    continue_exec = args.continue_exec
    find_lina = args.find_lina
    reboot = args.reboot
    dolog = args.dolog

    # Default values from one config file
    scriptdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    userdir = os.path.expanduser("~")
    dirs = [os.path.join(scriptdir, "asadbg.cfg"), os.path.join(userdir, "asadbg.cfg")]
    try:
        dirs.insert(0, os.environ["ASADBG_CONFIG"])
    except:
        pass
    if args.asadbg_config:
        dirs.insert(0, args.asadbg_config)
    for confpath in dirs:
        if os.path.exists(confpath):
            logmsg("Using config file: %s" % confpath)
            cp = configparser.SafeConfigParser()
            cp.read(confpath)
            if cp.has_option("GLOBAL", "gns3_host"):
                gns3_host = cp.get("GLOBAL", "gns3_host")
            if cp.has_option("GLOBAL", "serial_port"):
                serial_port = cp.get("GLOBAL", "serial_port")
            if cp.has_option("GLOBAL", "asadb_file"):
                asadb_file = cp.get("GLOBAL", "asadb_file")
            if cp.has_option("GLOBAL", "scripts"):
                s = cp.get("GLOBAL", "scripts")
                scripts.extend(s.split(","))
            if name == None:
                break
            if not cp.has_section(name):
                logmsg("Could not find section: '%s' in config" % name)
                break
            logmsg("Found section: '%s' in config" % name)
            if cp.has_option(name, "gns3_host"):
                gns3_host = cp.get(name, "gns3_host")
            if cp.has_option(name, "serial_port"):
                serial_port = cp.get(name, "serial_port")
            if cp.has_option(name, "asadb_file"):
                asadb_file = cp.get(name, "asadb_file")
            if cp.has_option(name, "version"):
                version = cp.get(name, "version")
            if cp.has_option(name, "arch"):
                arch = cp.get(name, "arch")
            if cp.has_option(name, "rootfs_path"):
                rootfs_path = cp.get(name, "rootfs_path")
            if cp.has_option(name, "firmware_type"):
                firmware_type = cp.get(name, "firmware_type")
            if cp.has_option(name, "attach_gdb"):
                attach_gdb = cp.getboolean(name, "attach_gdb")
            if cp.has_option(name, "firmware"):
                firmware = cp.get(name, "firmware")
            if cp.has_option(name, "config"):
                config = cp.get(name, "config")
            if cp.has_option(name, "gns3_port"):
                gns3_port = cp.get(name, "gns3_port")
            if cp.has_option(name, "scripts"):
                s = cp.get(name, "scripts")
                scripts.extend(s.split(","))
            break

    # scripts from config file are loaded before those from command line
    if args.scripts:
        scripts.extend(args.scripts)

    # Override values if specified from the command line
    if args.version != None:
        version = args.version
    if args.arch != None:
        arch = args.arch
    if args.rootfs_path != None:
        rootfs_path = args.rootfs_path
    if args.firmware_type != None:
        firmware_type = args.firmware_type
    if args.attach_gdb != False:
        attach_gdb = args.attach_gdb
    if args.firmware != None:
        firmware = args.firmware
    if args.config != None:
        config = args.config
    if args.gns3_host != None:
        gns3_host = args.gns3_host
    if args.gns3_port != None:
        gns3_port = args.gns3_port
    if args.serial_port != None:
        serial_port = args.serial_port
    if args.asadb_file != None:
        asadb_file = args.asadb_file

    if attach_gdb:
        try:
            GDB = os.environ["GDB"]
        except:
            GDB="gdb"
        logmsg("Using gdb from path: '%s'" % GDB)

    if attach_gdb and not version:
        logmsg("Error: You must specify a valid ASA version for attaching to gdb")
        sys.exit()
    if version and "." in version:
        logmsg("Stripping dots from version: %s" % version)
        version = version.replace(".", "")
    if attach_gdb:
        if asadb_file == None:
            logmsg("Error: You must specify a db file using --asadb-file")
            sys.exit()
        logmsg("Using db file: '%s'" % asadb_file)

        if rootfs_path == None:
            logmsg("Error: Maybe specify extracted path with --rootfs-path")
            sys.exit()

        if not is_debugging_path_ok(version, rootfs_path, asadb_file, arch):
            logmsg("Error: You must extract the firmware to the configured path to debug it")
            sys.exit()
        logmsg("Going to debug...")
    else:
        logmsg("Going to just load firmware/config...")

    if arch == "gns3":
        if not attach_gdb:
            logmsg("Error: In GNS3, we only support attaching to a listening gdbserver")
            sys.exit()
        if not gns3_host or not gns3_port:
            logmsg("Error: You need to define a valid host/port for debugging GNS3")
            sys.exit()
        else:
            logmsg("Using GNS3 emulator %s:%s" % (gns3_host, gns3_port))
    else:
        logmsg("Using serial port: %s" % serial_port)
        if attach_gdb and getpass.getuser() != "root":
            try:
                # In case you are in dialout group or whatever
                with open(serial_port, "r") as tmp:
                    tmp.close()
            except:
                logmsg("Error: Can't access serial. It does not exist, is already used or you need root")
                sys.exit()

        if attach_gdb and firmware_type != "rooted" and firmware_type != "gdb":
            logmsg("ERROR: You need a gdb-enabled or rooted firmware to debug REAL ASA")
            logmsg('ERROR: Specify "rooted" or "gdb" with firmware_type if this is the case')
            sys.exit()
        # We need to enable GDB at boot for rooted firmware only
        enable_gdb = False
        if firmware_type == "rooted" and attach_gdb == True:
            enable_gdb = True

        # we support specifying the config file with something like "../config/config-841-snmp-ssh"
        if config != None:
            config = os.path.basename(config)

        ser = serial.Serial(serial_port, 9600, timeout=1)
        if reboot:
            comm.reboot_over_serial(ser)
        if firmware == None:
            logmsg("Warning: no firmware specified, using default firmware")
        if config == None:
            logmsg("Warning: no config specified, using default config")
        if firmware_type == "rooted":
            logmsg("Loading rooted '%s' with '%s'..." % (firmware, config))
            comm.boot_router_cli(ser, firmware, enable_gdb, boot_config=config)
        else:
            logmsg("Loading '%s' with '%s'..." % (firmware, config))
            comm.boot_router_cli_non_rooted(ser, firmware, boot_config=config)

    if attach_gdb:
        # gdbinit file patched and written before executing gdb
        gdbinit_data = open('template_gdbinit', 'rb').read().decode('UTF-8')

        logmsg("Starting gdb now...")
        gdbinitfile = build_gdbinit(rootfs_path=rootfs_path, targetdb=asadb_file,
                                    gdbinit=gdbinit_data, remote_ip=gns3_host,
                                    remote_port=gns3_port, serial_port=serial_port,
                                    version=version, arch=arch,
                                    scripts=scripts, use_retsync=ret_sync,
                                    cont=continue_exec,
                                    find_lina=find_lina, use_display=display)
        os.system("%s -x %s --quiet" % (GDB, gdbinitfile))
    else:
        start_shell(serial_port, doLog=dolog)
