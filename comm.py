#!/usr/bin/python3
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Tools to use serial / telnet / SSH to issue commands, reboot the router, 
# transfer files between the host and the router, etc.
#
# Dependencies:
# - sudo pip3 install paramiko
#   http://jessenoller.com/blog/2009/02/05/ssh-programming-with-paramiko-completely-different
# - sudo apt-get install sshpass
#   allow to scp specifying the password from the command line
#
# Known problems
# - sometimes the scp commands returns "Write failed: Broken pipe" but the file 
#   is actually transfered successfully anyway.
# - you must have connected to the router first so your key is added. Otherwise
#   the script does not handle the "The authenticity of host '192.168.210.77
#   (192.168.210.77)' can't be established. RSA key fingerprint is
#   c2:8d:41:05:a4:7e:54:26:dd:be:88:c4:1a:84:dc:b1. Are you sure you want to
#   continue connecting (yes/no)?" question and nothing is sent

import paramiko
import time
import argparse
import sys, re
import os, serial, socket, threading
from telnetlib import Telnet

def logmsg(s, end=None):
    if type(s) == str:
        if end != None:
            print("[comm] " + s, end=end)
        else:
            print("[comm] " + s)
    else:
        print(s)

try:
    os.environ["ASATOOLS"]
except:
    logmsg("Error: Consider using source env.sh (use sudo -E to preserve environment)")
    sys.exit()
SSHUSER = os.environ["ASA_USER"]
SSHPASSWORD = os.environ["ASA_PASS"]

############ Helpers ############
    
### Serial helpers

# Seems to be a sporadic kernel bug that causes exceptions
def serial_read(ser, rlen):
    tries = 0
    while tries < 4:
        try:
            return ser.read(rlen).decode('UTF-8', errors="replace")
        except serial.SerialException:
            tries += 1

def serial_write(ser, data):
    return ser.write(bytes(data, encoding="UTF8"))

### SSH helpers

def read_channel(stdout, wait=2):
    # http://stackoverflow.com/questions/35266753/paramiko-python-module-hangs-at-stdout-read
    # BUG: https://github.com/paramiko/paramiko/issues/109
    # when it comes to stdout.read() , it hangs...
    # it is due to stdout.channel.eof_received == 0
    # a workaround is to wait for a timeout, force stdout.channel.close() 
    # and then stdout.read()
    time.sleep(wait)
    stdout.channel.shutdown_write()
#    stdout.channel.close()
    return stdout.read().decode('UTF-8', errors="replace")

############ Generic serial/telnet/ssh ############

PROTOCOL_SERIAL = "serial"
PROTOCOL_TELNET = "telnet"
PROTOCOL_SSH    = "ssh"

SHELLTYPE_CISCO_CLI = "cli"
SHELLTYPE_DEBUG_SHELL = "bash"

class Comm:
    def __init__(self, shell_type=SHELLTYPE_CISCO_CLI):
        self.tn = None
        self.ser = None
        self.ssh = None
        self.ssh_stdin = None
        self.ssh_stdout = None
        self.ssh_stderr = None
        self.shell_type = shell_type
        if self.shell_type == SHELLTYPE_CISCO_CLI:
            logmsg("Assuming a Cisco CLI")
            self.shell = b">"
        elif self.shell_type == SHELLTYPE_DEBUG_SHELL:
            logmsg("Assuming a debug shell")
            self.shell = b"bash-4.2#"
    
    def info(self):
        if self.tn != None:
            logmsg("Telnet: %s:%d" % (self.tn.host, self.tn.port))
        elif self.ser != None:
            logmsg("Serial: %s" % self.ser.port)
        elif self.ssh != None:
            t = self.ssh.get_transport()
            logmsg("SSH: %s:%d" % t.getpeername())
        else:
            logmsg("Comm.info failed")

    def read(self, byte=None, show=True, wait=2):
        if byte == None:
            byte = self.shell
        if self.tn != None:
            return self.telnet_read(byte)
        elif self.ser != None:
            return self.serial_read()
        elif self.ssh != None:
            return self.ssh_read(wait)
        else:
            logmsg("Comm.read failed")
            return None

    def write(self, dat):
        if self.tn != None:
            return self.telnet_write(dat)
        elif self.ser != None:
            return self.serial_write(dat)
        elif self.ssh != None:
            return self.ssh_write(dat)
        else:
            logmsg("Comm.write failed")
            return None

    # XXX - We should change this to detect errors and flag which line caused
    # the problem?
    def write_config(self, config):
        for line in config.readlines():
            if line.startswith("#"):
                continue # skip comments
            try:
                self.write(line + '\n')
                print(self.read("#"))
            except socket.timeout:
                logmsg("Warning: Telnet timed out")
                self.close()
        logmsg("Config should be written")


    def flush(self):
        if self.ssh != None:
            self.ssh_stdin.flush()

    def close(self):
        if self.tn != None:
            self.tn.close()
        elif self.ser != None:
            self.ser.close()
        elif self.ssh != None:
            self.ssh.close()

    def init_telnet(self, host):
        # 5 is arbitrary for now
        self.tn = Telnet(host[0], host[1], 5)

        if self.tn == None:
            logmsg("Warning: Couldn't establish telnet connection")
            return
        try:
            logmsg("Telnet connection established")
            if self.shell_type == SHELLTYPE_CISCO_CLI:
                self.tn.write(b"\n")
                self.tn.write(b"\n")
                # We do this just in case we are in an enabled shell already
                self.tn.write(b"disable\n")
                logmsg("Waiting for prompt")
                self.tn.read_until(self.shell)
                logmsg("Got prompt")
                self.tn.write(b"enable\n")
                self.tn.read_until(b"Password:")
                self.tn.write(b"\n")
                self.tn.read_until(b"#")
                logmsg("Got root console")
                logmsg("Set unlimited terminal pager")
                self.tn.write(b"terminal pager 0\n")
                self.tn.read_until(b"#")
    #            self.tn.write(b"show running\n")
    #            result = self.tn.read_until(b"ciscoasa#")
    #            print(result.decode('utf-8'))
                self.tn.write(b"disable\n")
                logmsg("Lowered privs")
            elif self.shell_type == SHELLTYPE_DEBUG_SHELL:
                self.tn.write(b"\n")
                self.tn.write(b"\n")
                logmsg("Waiting for prompt")
                self.tn.read_until(self.shell)
                logmsg("Got prompt")

        except socket.timeout:
            logmsg("Warning: Telnet timed out")
            self.close()

    def telnet_read(self, byte=None):
        if byte == None:
            byte = self.shell
        return self.tn.read_until(byte)

    def telnet_write(self, dat):
        self.tn.write(dat + b"\n")
        return

    def init_serial(self, port="/dev/ttyUSB0"):
        self.ser = serial.Serial(port, 9600, timeout=1)

    def serial_read(self):
        return self.ser.read(4096).decode('UTF-8', errors="replace")

    def serial_write(self, data):
        self.ser.write(bytes(data + "\n", encoding="UTF-8"))
        return

    def init_ssh(self, host, user, password, connectOnly=False):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(host, username=user, password=password)
        except Exception as e:
            print("Unable to connect over SSH: %s" % str(e))
            sys.exit(0)
        if connectOnly:
            return
        self.ssh_stdin, self.ssh_stdout, self.ssh_stderr = self.ssh.exec_command('enable\n')
        self.ssh_stdin.write('\n')

    def ssh_read(self, wait=2j):
        return read_channel(self.ssh_stdout, wait)

    def ssh_write(self, dat):
        self.ssh_stdin.write(dat)
        return

def start_lina(comm):
    logmsg("Restarting lina now...")
    comm.write(b"/asa/scripts/lina_start.sh\n")
    comm.flush()
    #data = comm.read()
    #print(data)

def execute_cmd(comm, cmd, config_t=False, show=True, read=True):
    comm.write('enable\n') 
    comm.write('\n') # hit enter (no password)
    if config_t == True:
        comm.write('config t\n') 
    comm.flush()
    comm.write(cmd)
    comm.write('\n') # just in case...
    comm.flush()
    if read:
        res = comm.read()
        if show:
            print(res)
        return res
    return None

def reboot_router(comm):
    logmsg("Rebooting router now...")
    comm.info()

    comm.write('\n') # hit enter
    # Just in case someone didn't actually send it...
    comm.write('enable\n') # hit enter (no password)
    comm.write('\n') # hit enter (no password)
    comm.flush()
    comm.write('reload noconfirm\n')
    comm.flush()
    data = comm.read()
    #logmsg("Received %d bytes" % len(data))
    #print(data)
    if "SHUTDOWN NOW" in data:
        logmsg("Shutdown successfully executed")
        res = True
    else:
        if comm.ser != None:
            comm.write('reboot -f\n') # hit enter (no password)
        else:
            logmsg("Not sure if shutdown worked")
        res = False
    return res

def get_version(comm, show=False):
    logmsg("Retrieving version now...")
    comm.info()
    
    out = execute_cmd(comm, "show version", show=show)
    #print("-"*10)
    #print(out)
    #print("-"*10)
    res = re.findall("Cisco Adaptive Security Appliance Software Version (.*) \r\n", out)
    if not res:
        logmsg("Warning: Could not determine the version")
    else:
        logmsg("Detected version: %s" % res[0])

def delay_checkheaps(comm, show=False):
    logmsg("Delaying checkheaps now...")
    comm.info()

    # We must use max value as 0 doesn't disable
    # But this will run every 24 days now so should be okay :P
    execute_cmd(comm, "checkheaps check-interval 2147483", config_t=True, show=show)

def enable_checkheaps(comm, show=False):
    logmsg("Enabling checkheaps every second now...")
    comm.info()

    # This is to force checkheaps to run very often
    execute_cmd(comm, "checkheaps check-interval 1", config_t=True, show=show)
    
def show_checkheaps(comm, show=True):
    logmsg("Showing checkheaps now...")
    comm.info()

    execute_cmd(comm, "show checkheaps", config_t=True, show=show)
    
def is_file_on_router(comm, filename, ip="192.168.210.77"):
    found = True
    comm.flush()
    comm.write('dir %s\n' % filename)
    comm.flush()
    res = comm.read()
    #print(res)
    if "(No such file or directory)" in res:
        found = False
    return found

def upload_file(comm, localpath, remotepath, overwrite=False, ip="192.168.210.77", oldssh=False, sshuser="user", sshpass="user"):
    logmsg("Uploading file...")
    comm.info()

    if is_file_on_router(comm, remotepath):
        if overwrite:
            logmsg("Warning: Overwriting file: %s" % remotepath)
        else:
            logmsg("Warning: Skipping existing file: %s" % remotepath)
            return
    logmsg("Uploading: %s..." % remotepath)
    if oldssh:
        scp_opts = ""
    else:
        scp_opts = "-oKexAlgorithms=+diffie-hellman-group1-sha1"
    cmd = "sshpass -p %s scp %s %s %s@%s:%s" % (sshpass, scp_opts, localpath, sshuser, ip, remotepath)
    logmsg("Executing '%s'..." % cmd)
    os.system(cmd)

# overwrite local path
def download_file(comm, localpath, remotepath, ip="192.168.210.77", oldssh=False, sshuser="user", sshpass="user"):
    if not is_file_on_router(comm, remotepath, ip):
        logmsg("Warning: Can't download file because file doesn't exist on router: %s" % remotepath)
        return
    logmsg("Downloading: %s..." % remotepath)
    if oldssh:
        scp_opts = ""
    else:
        scp_opts = "-oKexAlgorithms=+diffie-hellman-group1-sha1"
    cmd = "sshpass -p %s scp %s %s@%s:%s %s" % (sshpass, scp_opts, sshuser, ip, remotepath, localpath)
    logmsg("Executing '%s'" % cmd)
    os.system(cmd)

# https://supportforums.cisco.com/document/9936/how-clear-isakmp-and-ipsec-sas-pix-firewalls-and-routers
def clear_ike_sa(comm, show=False):
    logmsg("Clearing IKE SAs...")
    comm.info()
    
    comm.flush()
    comm.write('clear crypto isakmp sa\n')
    comm.flush()
    comm.write('show crypto isakmp sa\n')
    comm.flush()
    res = comm.read()
    if show:
        print(res)
    if "There are no IKEv1 SAs" in res and "There are no IKEv2 SAs" in res:
        return True
    return False

# http://www.cisco.com/c/en/us/support/docs/security-vpn/webvpn-ssl-vpn/119417-config-asa-00.html
def logoff_webvpn_sessions(comm, show=False):
    logmsg("Clearing WebVPN sessions...")
    comm.info()
    
    comm.flush()
    comm.write('vpn-sessiondb logoff webvpn noconfirm\n')
    comm.flush()
    comm.write('show vpn-sessiondb webvpn\n')
    comm.flush()
    res = comm.read()
    if show:
        print(res)
    if "There are presently no active sessions" in res:
        return True
    return False

def compute_md5(comm, filename, show=False):
    execute_cmd(comm, "verify /md5 %s\n" % filename, show=False, config_t=True, read=False)
    comm.flush()
    logmsg("Calculating MD5. Will take 20 seconds... ")
    buf = comm.read(wait=20)
    if "(No such file or directory)" in buf:
        logmsg("File %s not found. Skipping it" % filename)
        sys.exit()
    try:
        res = buf.split('=')[1][1:33]
    except IndexError:
        logmsg("[!] Can't find MD5")
        print(buf)
    else:
        logmsg("%s = %s" % (filename, res))

############ Boot sequence parsing (over serial) ############
            
# use for non-rooted firmware (unmodified or with gdb enabled)
def boot_router_cli_non_rooted(ser, boot_firmware, boot_config=None):
    logmsg("Waiting boot...")

    # if firmware specified, we get a bootrom shell
    # and boot the specified firmware
    if boot_firmware != None:
        # boot to bootrom
        while True:
            # H
            try:
                data = serial_read(ser, 4096)

            # Handle error: serial.serialutil.SerialException: device reports
            # readiness to read but returned no data (device disconnected or multiple
            # access on port?)
            # Seen sporadically on Ubuntu 16.04
            except serial.SerialException as e:
                continue

            if data == None:
                continue
            #print("Phase 0 - Received %d bytes" % len(data))
            if len(data) == 0:
                print(".", end='', flush=True)
            else:
                print(data, end='', flush=True)
            if "rommon #0>" in data:
                break
            # enter bootrom mode
            if "Use BREAK or ESC to interrupt boot." in data or " seconds." in data:
                serial_write(ser, "\x1b")
        # in bootrom shell
        # note the extra space before the "boot" command. It looks like the first
        # character we send is ignored sometimes so we add this.
        # But we still retry below if it failed anyway
        time.sleep(0.5)
        if boot_config == None:
            serial_write(ser, " boot %s\n" % boot_firmware)
        else:
            serial_write(ser, " boot %s cfg=%s\n" % (boot_firmware, boot_config))
        time.sleep(0.5)
        data = serial_read(ser, 4096)
        if len(data) == 0:
            print(".", end='', flush=True)
        else:
            print(data, end='', flush=True)
        if "Invalid or incorrect command.  Use 'help' for help." in data or \
            "Use 'help' for help." in data:
            time.sleep(0.5)
            if boot_config == None:
                serial_write(ser, " boot %s\n" % boot_firmware)
            else:
                serial_write(ser, " boot %s cfg=%s\n" % (boot_firmware, boot_config))
        if "Cannot find %s" % boot_firmware in data or \
            "unable to boot an image" in data:
            print("")
            logmsg("Firmware is corrupt or does not exist. Exiting now")
            sys.exit()

    # give some time because it doesn't continue right away
    #time.sleep(10)

    # We detect if a cisco ASA CLI shell is available
    now = time.time()
    while True:
        later = time.time()
        diff = int(later - now)
        if diff > 60*3:
            logmsg("CLI not detected but assuming it has finished booting anyway...")
            break
        # XXX - here if we didn't detect the right pattern to break out of this loop
        # we get stuck here forever reading 0 bytes, so may be good to add a timeout
        # to leave the loop after a certain time as an additional safety measure?
        data = serial_read(ser, 4096)
        #print("Phase 2 - Received %d bytes" % len(data))
        if len(data) == 0:
            print(".", end='', flush=True)
        else:
            print(data, end='', flush=True)
        # we check this first as we want to detect it even if it finished booting
        if "WARNING: BOOT variable added, but unable to find disk0:/%s" % str(boot_config) in data or \
            "ERROR: MIGRATION - Could not get the startup configuration." in data:
            print("")
            logmsg("Configuration file does not exist. Exiting now")
            sys.exit()
        if "This is an ASA image and cannot be loaded on a PIX platform" in data:
            print("")
            logmsg("Invalid firmware. Exiting now")
            sys.exit()
        if "Rebooting..." in data:
            print("")
            logmsg("ASA has rebooted, should not happen. Exiting now")
            sys.exit()
        # avoid waiting 10 seconds
        if "Use SPACE to begin boot immediately." in data or " seconds." in data:
            serial_write(ser, " ")
        if "unable to boot an image" in data:
            logmsg("ERROR: Could not find the firmware. Save it on the CF card first.")
            sys.exit()
        if "Type help or '?' for a list of available commands." in data or \
            "a list of available commands." in data or \
            "ciscoasa>" in data:
            logmsg("CLI detected - boot finished.")
            break
        if "Remote debugging using /dev/ttyS0" in data or \
            "/dev/ttyS0" in data:
            logmsg("gdb detected - boot finished.")
            break
         

    logmsg("Boot should be finished now?")

# use for rooted firmware
def boot_router_cli(ser, boot_firmware, enable_gdb=False, boot_config=None):
    logmsg("Waiting boot...")

    # if firmware specified, we get a bootrom shell
    # and boot the specified firmware
    if boot_firmware != None:
        # boot to bootrom
        while True:
            data = serial_read(ser, 4096)
            #print("Phase 0 - Received %d bytes" % len(data))
            if data == None:
                continue
            if len(data) == 0:
                print(".", end='', flush=True)
            else:
                print(data, end='', flush=True)
            if "rommon #0>" in data:
                break
            # enter bootrom mode
            if "Use BREAK or ESC to interrupt boot." in data or " seconds." in data:
                serial_write(ser, "\x1b")
        # in bootrom shell
        # note the extra space before the "boot" command. It looks like the first
        # character we send is ignored sometimes so we add this.
        # But we still retry below if it failed anyway
        time.sleep(0.5)
        if boot_config == None:
            serial_write(ser, " boot %s\n" % boot_firmware)
        else:
            serial_write(ser, " boot %s cfg=%s\n" % (boot_firmware, boot_config))
        time.sleep(0.5)
        data = serial_read(ser, 4096)
        if len(data) == 0:
            print(".", end='', flush=True)
        else:
            print(data, end='', flush=True)
        if "Invalid or incorrect command.  Use 'help' for help." in data or \
            "Use 'help' for help." in data:
            time.sleep(0.5)
            if boot_config == None:
                serial_write(ser, " boot %s\n" % boot_firmware)
            else:
                serial_write(ser, " boot %s cfg=%s\n" % (boot_firmware, boot_config))
        if "Cannot find %s" % boot_firmware in data or \
            "unable to boot an image" in data:
            print("")
            logmsg("Firmware does not exist. Exiting now")
            sys.exit()

    # boot Linux kernel and detect when we get a root shell
    now = time.time()
    while True:
        later = time.time()
        diff = int(later - now)
        if diff > 60*2:
            logmsg("shell not detected but assuming we have it anyway...")
            break
        data = serial_read(ser, 4096)
        #print("Phase 1 - Received %d bytes" % len(data))
        if len(data) == 0:
            print(".", end='', flush=True)
        else:
            print(data, end='', flush=True)
        if "/bin/sh: can't access tty; job control turned off" in data or \
            "job control turned off" in data:
            break
        if "/bin/sh: can't access tty;" in data:
            data = serial_read(ser, 4096)
            print(data, end='', flush=True)
            break
        # avoid waiting 10 seconds
        if "Use SPACE to begin boot immediately." in data or " seconds." in data:
            serial_write(ser, " ")
        if "unable to boot an image" in data:
            logmsg("ERROR: Could not find the firmware. Save it on the CF card first.")
            sys.exit()

    # we got a root shell so we execute some commands to finalize boot
    if enable_gdb:
        serial_write(ser, "sed -i 's/#\(.*\)ttyUSB0\(.*\)/\\1ttyS0\\2/' /asa/scripts/rcS\n")
        data = serial_read(ser, 4096)
        if "^@sed: not found" in data:
            logmsg("Warning: Reussing sed command...")
            serial_write(ser, "sed -i 's/#\(.*\)ttyUSB0\(.*\)/\\1ttyS0\\2/' /asa/scripts/rcS\n")
            data = serial_read(ser, 4096)
        print(data, end='', flush=True)
    serial_write(ser, 'exec /sbin/init\n')

    # give some time because it doesn't continue right away
    #time.sleep(10)

    # we have booted. We detect if a gdbserver or a cisco ASA CLI shell is available
    now = time.time()
    while True:
        later = time.time()
        diff = int(later - now)
        if diff > 60*2:
            logmsg("CLI not detected but assuming it has finished booting anyway...")
            break
        # XXX - here if we didn't detect the right pattern to break out of this loop
        # we get stuck here forever reading 0 bytes, so may be good to add a timeout
        # to leave the loop after a certain time as an additional safety measure?
        data = serial_read(ser, 4096)
        #print("Phase 2 - Received %d bytes" % len(data))
        if len(data) == 0:
            print(".", end='', flush=True)
        else:
            print(data, end='', flush=True)
        # we check this first as we want to detect it even if it finished booting
        if "WARNING: BOOT variable added, but unable to find disk0:/%s" % str(boot_config) in data or \
            "ERROR: MIGRATION - Could not get the startup configuration." in data:
            print("")
            logmsg("Configuration file does not exist. Exiting now")
            sys.exit()
        if "This is an ASA image and cannot be loaded on a PIX platform" in data:
            print("")
            logmsg("Invalid firmware. Exiting now")
            sys.exit()
        if "Rebooting..." in data:
            print("")
            logmsg("ASA has rebooted, should not happen. Exiting now")
            sys.exit()
        if "Remote debugging using /dev/ttyS0" in data or \
            "/dev/ttyS0" in data:
            break
        if "Type help or '?' for a list of available commands." in data or \
            "a list of available commands." in data or \
            "ciscoasa>" in data:
            logmsg("CLI detected - boot finished.")
            break

    logmsg("Boot should be finished now?")

############ Serial (not supporting Comm class) ############

def execute_cmd_over_serial(cmd, ser, confirm_list=[], config_t=False):
    data_out = ''
    logmsg("Executing command: '%s' over serial: '%s'" % (cmd, ser.port))
    # flush previous prompt
    serial_read(ser, 4096)
    # this may fail if we are already in enable mode but we don't really care
    # XXX - sometimes this fails with:
    #     input_interrupt, count = 1 c = 101 ('e')
    #     input_interrupt, count = 1 c = 110 ('n')
    #     input_interrupt, count = 1 c = 97 ('a')
    #     input_interrupt, count = 1 c = 98 ('b')
    #     input_interrupt, count = 1 c = 108 ('l')
    #     input_interrupt, count = 1 c = 101 ('e')
    #     input_interrupt, count = 1 c = 10 ('#')
    # But don't know how to fix yet

    serial_write(ser, "enable\n")
    dat = serial_read(ser, 4096)
    if dat == None:
        logmsg("Warning: Bad read")
        return None
    serial_write(ser, "\n\n") # hit enter (no password)
    res = re.findall(".*enable: not found.*", dat)
    if res:
        logmsg("Warning: Doesn't appear to be in cisco shell connected to serial.")
        return None

    print(serial_read(ser, 4096))
    # so we don't have any "<--- More --->" and don't have to scroll or hit "space"
    # XXX - data is still incomplete below as we only get the first 4k bytes or less
    #       but we don't need more for now
    serial_write(ser, 'terminal pager 0\n')
    print(serial_read(ser, 4096))
    if config_t:
        serial_write(ser, "config terminal\n")
        print(serial_read(ser, 4096))
    serial_write(ser, '%s\n' % cmd)
    while True:
        data = serial_read(ser, 4096)
        confirm = False
        print(data)
        if data == None:
            continue
        data_out += data
        for e in confirm_list:
            if e in data:
                confirm = True
                break
        if not confirm:
            break
        serial_write(ser, "\n") # hit enter (confirm)

    # exit from config 
    if config_t:
        serial_write(ser, "exit\n")
        print(serial_read(ser, 4096))

    return data_out

def reboot_over_serial(ser):
    result = execute_cmd_over_serial("reload noconfirm", ser)
    if result == None:
        # This tries to reboot it under the assumption it's in an init shell
        serial_write(ser, "reboot -f\n")

def enable_checkheaps_over_serial(ser):
    result = execute_cmd_over_serial("checkheaps check-interval 1", ser, config_t=True)

def disable_crashdumps_over_serial(ser):
    result = execute_cmd_over_serial("crashinfo console disable", ser, config_t=True)
    result = execute_cmd_over_serial("crashinfo save disable", ser, config_t=True)
    
# We assume the ASA has been booted with the config file and with the ASA version that we want to 
# use for the next boot (and all following ones). Consequently, both "boot config" and "boot system"
# are defined and are part of the "running-config"
def setup_boot_config_and_system(ser, configfile, systemfile):
    # it should not be needed to set the two following "boot ..." commands below as we suppose the ASA
    # has already booted with this but in practice it is not always set so we set it again as it is better
    # safe than sorry :)
    execute_cmd_over_serial("show running-config boot", ser) # debug
    # we only execute "config t" once
    execute_cmd_over_serial("boot system %s" % systemfile, ser, config_t=True)
    execute_cmd_over_serial("boot config %s" % configfile, ser)
    execute_cmd_over_serial("show running-config boot", ser) # debug
    # we don't use "write memory" as it will effectively replace the config file defined in 
    # "boot config ..." instead of replacing the startup-config
    execute_cmd_over_serial("copy running-config startup-config", ser, confirm_list=["Source filename"])
    reboot_over_serial(ser)

def detect_crash_over_console(ser):
    ret = True
    now = time.time()
    while True:
        later = time.time()
        diff = int(later - now)
        if diff > 40:
            logmsg("no crash detected so exploit probably completely failed...")
            ret = False
            break
        data = serial_read(ser, 4096)
        logmsg("Phase 3 - Received %d bytes" % len(data))
        if len(data) == 0:
            print(".", end='', flush=True)
        else:
            print(data, end='', flush=True)
        # if crashinfo are enabled...
        if "CURRENT MALLOC CHUNK" in data or \
           "Begin to dump crashinfo to flash...." in data or \
            "NEXT MALLOC CHUNK" in data or \
            "Crashinfo collected on" in data or \
            "Abort: Unknown" in data or \
            "Traceback:" in data or \
            "Stack dump: " in data:
            ret = True
            break
        # and if crashinfo are disabled...
        elif "core0: An internal error occurred." in data or \
            "malloc.c" in data or \
            "assertion" in data or \
            "Process shutdown finished" in data:
            ret = True
            break
    return ret

############ Debug shell ############

# Interact with debug shell
def gdb_ctrl_c_thread_interact(revHost, revPort):
    from telnetlib import Telnet

    logmsg("Thread: Listening on %s:%d..." % (revHost, revPort))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(10)
    s.bind((revHost, revPort))
    s.listen(5)
    try:
        cli = s.accept()[0]
    except socket.timeout:
        logmsg("Thread: [!] Nothing received after 10 seconds. Try pinging the router to check if it is still alive?")
    else:
        s.close()
        logmsg("Thread: Got connect-back")
        # We wait a bit so the Python main thread can finish establishing the SSH connection
        # and effectively be waiting for this 2nd thread to finish
        time.sleep(0.5)

        t = Telnet()
        t.sock = cli
        data = t.read_until(b"#")
        if b"sh: no job control in this shell" not in data and b"/bin/sh: can't access tty;" not in data:
            logmsg("[!] Warning: not a debug shell?")
            print(data)
            t.close()
            return
        t.write(b"ps aux|grep lina\n")
        data = t.read_until(b"#")
        lines = data.split(b"\n")
        pid = None
        for l in lines:
            # Output is different based on busybox. Parses one of the below:
            # b'root      1673  2.9 25.5 1588464 436188 ?      S<Ll Sep29 133:17 /asa/bin/lina -p 1625 -t -g -l'
            # b'  518 root     /asa/bin/lina -p 513 -t -g -l'
            # but we want to avoid the gdbserver one:
            # b'  515 root     gdbserver /dev/ttyS0 /asa/bin/lina -p 513 -t -g -l'
            if b"/asa/bin/lina -p" in l and b"gdbserver" not in l:
                elts = l.split()
                try:
                    pid = int(elts[1])
                except ValueError:
                    pid = int(elts[0])
                logmsg("Thread: Found lina PID: %d" % pid)
                break
        if pid == None:
            logmsg("Thread: Error: Can't find lina PID")
            t.close()
            return
        logmsg("Thread: Sending SIGTRAP to lina PID")
        t.write(bytes("kill -5 %d\n" % pid, encoding="utf-8"))
        #data = t.read_until(b"#")
        t.close()
        logmsg("Thread: Done")

# 4444 is the port we use everywhere else for the debug shell
# so we can safely hardcode it
def gdb_ctrl_c_main(comm, target_ip, user, password, revHost="0.0.0.0", revPort=4444):
    th = threading.Thread(target=gdb_ctrl_c_thread_interact, args=(revHost, revPort))
    th.daemon = True
    th.start()
    
    logmsg("Triggering SSH connection")
    comm.init_ssh(target_ip, user, password, connectOnly=True)

    logmsg("Waiting for thread to finish")
    while True:
        th.join(10000)
        if not th.isAlive():
            break
    logmsg("Done")

############ main ############

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--comm', dest='comm_type', default=PROTOCOL_SERIAL, \
                        help="Communication type {serial(default), telnet, ssh}")
    parser.add_argument('--shell', dest='shell_type', default=SHELLTYPE_CISCO_CLI, \
                        help="Communication type {cli(default), bash}")
    parser.add_argument('--port', dest='target_port', default=None, 
                        help='Specify a custom serial (e.g. "/dev/ttyUSB0")/telnet (e.g. 5000) port)')
    parser.add_argument('--ip', dest='target_ip', default="192.168.210.77", 
                        help="Cisco ASA/GNS3 IP address")
    parser.add_argument('--user', dest='user', default=None, help='User for SSH')
    parser.add_argument('--pass', dest='password', default=None, help='Password for SSH')
    parser.add_argument('--reboot', dest='reboot', action="store_true",
                        help='Reboot router (serial, SSH)')
    parser.add_argument('--version', dest='version', default=False,
                        action="store_true", help="Get the version (serial, SSH)")
    parser.add_argument('--disable-checkheaps', dest='delay_checkheaps', default=False, action="store_true", 
                        help='Disable checkheaps default timeout (60 sec)')
    parser.add_argument('--show-checkheaps', dest='show_checkheaps', default=False, action="store_true", 
                        help='Show checkheaps status')
    parser.add_argument('--upload', dest='upload', default=False, action="store_true", help='Upload over SSH')
    parser.add_argument('--force', dest='force', action="store_true", help='Overwrite existing files')
    parser.add_argument('--download', dest='download', default=False, action="store_true",
                        help='Download over SSH')
    parser.add_argument('--delete-ike-sa', dest='delete_ike_sa', action="store_true", help='Delete IKE SAs (serial, SSH)')
    parser.add_argument('--delete-webvpn-sessions', dest='delete_webvpn_sa', action="store_true", 
                        help='Delete WebVPN sessions (serial, SSH)')
    parser.add_argument('--md5', dest='md5', default=False,
                        action="store_true", help="Compute MD5 for files (serial, SSH)")
    parser.add_argument('--ctrlc', dest='ctrlc', default=False,
                        action="store_true", help="Simulate a CTRL^C in GDB by interacting with the debug shell")
    parser.add_argument('--input', dest='input', default=None, nargs="*", 
                        help='List of input files for other commands (eg: file1 file2 file3) (e.g.: --upload, --download, --md5)')
    parser.add_argument('--oldssh', default=False, action="store_true", 
                        help="Specify an old version of SSH (do not know specific command lines options and do not need them because unsecure :))")
    parser.add_argument('--cmd', dest='cmd', default=None, help='Command to run on the CLI (debugging)')
    parser.add_argument('--start-lina', dest='start_lina', default=False,
                        action="store_true", help="Use the ASA serial debug shell (Linux) to restart lina (Use telnet if GNS3)")
    parser.add_argument('-C', dest='cfg_file', default=None, help="File containing commands to use (e.g. config/setup_ssh.cfg)")
    args = parser.parse_args()

    # Override default values from env variables with arguments?
    if args.user != None:
        user = args.user
    else:
        user = SSHUSER
    if args.password != None:
        password = args.password
    else:
        password = SSHPASSWORD

    target_port = args.target_port
    comm_type = args.comm_type
    if args.upload != False or args.download != False or args.md5 != False or args.ctrlc != False:
        logmsg("Warning: using forced SSH")
        comm_type = PROTOCOL_SSH

    comm = Comm(shell_type=args.shell_type)
    if comm_type == PROTOCOL_TELNET:
        if target_port == None:
            logmsg("Error: You must specify a telnet port. Check GNS3 image config")
            sys.exit()
        comm.init_telnet((args.target_ip, int(target_port)))
    elif comm_type == PROTOCOL_SERIAL:
        if target_port == None:
            target_port = "/dev/ttyUSB0"
        comm.init_serial(port=target_port)
    elif comm_type == PROTOCOL_SSH:
        comm.init_ssh(args.target_ip, user, password)
    else:
        logmsg("You have to supply a valid communication type with --comm") 

    # NOTE: This is mostly for debugging
    if args.cmd != None:
        execute_cmd(comm, args.cmd)
        print(comm.read())

    if args.start_lina == True:
        start_lina(comm)
        comm.close()
        sys.exit()

    if args.reboot == True:
        reboot_router(comm)
        comm.close()
        sys.exit()

    if args.version == True:
        get_version(comm)
        comm.close()
        sys.exit()

    if args.delay_checkheaps == True:
        delay_checkheaps(comm)
        comm.close()
        sys.exit()
        
    if args.show_checkheaps == True:
        show_checkheaps(comm)
        comm.close()
        sys.exit()

    if args.delete_ike_sa == True:
        res = clear_ike_sa(comm)
        if res:
            logmsg("SAs successfully deleted")
        else:
            logmsg("Failed to delete SAs")
        sys.exit()
        
    if args.delete_webvpn_sa == True:
        res = logoff_webvpn_sessions(comm)
        if res:
            logmsg("WebVPN sessions successfully deleted")
        else:
            logmsg("Failed to delete WebVPN sessions")
        sys.exit()

    if comm_type == PROTOCOL_SSH:
        if args.upload == True:
            if not args.input:
                logmsg("You need to specify a valid file with --input")
                sys.exit()
            for f in args.input:
                upload_file(comm, f, os.path.basename(f), args.force, args.target_ip, args.oldssh, sshuser=user, sshpass=password)
                # It looks like because of read_channel() we have to close the previous connection
                # so we need to open a new one...
                comm.close()
                comm = Comm()
                comm.init_ssh(args.target_ip, user, password)
            comm.close()
            logmsg("Finished all tasks.")
            sys.exit()

        if args.download == True:
            if not args.input:
                logmsg("You need to specify a valid file with --input")
                sys.exit()
            for f in args.input:
                download_file(comm, os.path.basename(f), f, args.target_ip, args.oldssh)
                # It looks like because of read_channel() we have to close the previous connection
                # so we need to open a new one...
                comm.close()
                comm = Comm()
                comm.init_ssh(args.target_ip, user, password)
            comm.close()
            logmsg("Finished all tasks.")
            sys.exit()

        # XXX - we could need this using serial too
        if args.md5 == True:
            if not args.input:
                logmsg("You need to specify a valid file with --input")
                sys.exit()
            for f in args.input:
                compute_md5(comm, f)
                # It looks like because of read_channel() we have to close the previous connection
                # so we need to open a new one...
                try:
                    comm.close()
                    comm = Comm()
                    comm.init_ssh(args.target_ip, user, password)
                except:
                    # Sometimes paramiko fails and spits out a ton of errors
                    # even if it worked otherwise:
                    # ```
                    # Exception ignored in: <object repr() failed>
                    # Traceback (most recent call last):
                    #   File "/usr/local/lib/python3.5/dist-packages/paramiko/file.py", line 61, in __del__
                    #   File "/usr/local/lib/python3.5/dist-packages/paramiko/file.py", line 79, in close
                    #   File "/usr/local/lib/python3.5/dist-packages/paramiko/file.py", line 88, in flush
                    # TypeError: 'NoneType' object is not callable
                    # ```
                    # XXX - This is an attempt to avoid printing traceback to avoid
                    # confusion, but untested since I haven't hit it again yet
                    logmsg("Ignored paramiko error")
                    pass
            try:
                comm.close()
            except:
                logmsg("Ignored paramiko error")
                pass
            sys.exit()

        if args.ctrlc == True:
            #  we patched lina to accept any password when adding the debug shell
            password = ""
            gdb_ctrl_c_main(comm, args.target_ip, user, password)
            sys.exit()

    if args.cfg_file != None:
        with open(args.cfg_file, "r") as tmp:
            comm.write_config(tmp)
        sys.exit()
