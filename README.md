# asadbg

**asadbg** is a framework of tools to aid in automating live debugging of Cisco
ASA devices, as well as automating interaction with the Cisco CLI over
serial/ssh to quickly perform repetitive tasks.

* It wraps gdb
* It supports an `asadbg.cfg` configuration file to enable debugging different 
  versions easily
* It supports both real hardware and GNS3
* Optionally it uses ret-sync to allow a better debugging experience from IDA Pro
* It supports executing additional gdb scripts at boot
* It provides libraries that can be useful for automating tests across multiple firmware
  versions on real hardware
  
The main tool is `asadbg.py` and it will execute most of the other helper 
scripts. Note that you may need to initially use 
[asafw](https://github.com/nccgroup/asafw) to unpack firmware to get the best 
flavour of `asadbg`.

* `asadbg.py`: main tool used to debug ASAs
* `asdbg_hunt.py`/`asadbg_rename.py`: IDA Python script to use with [idahunt](https://github.com/nccgroup/idahunt) to import symbols for new targets

The following are automatically imported by `asadbg.py` but we give you some
information on what they are for:

* `asa_lib*.py`: gdb Python scripts to use 
  [libdlmalloc](https://github.com/nccgroup/libdlmalloc), 
  [libptmalloc](https://github.com/nccgroup/libptmalloc) and
  [libmempool](https://github.com/nccgroup/libmempool).
* `asa_sync.py`: gdb Python script to use 
  [ret-sync](https://github.com/bootleg/ret-sync/)
* `comm.py`: set of functions to communicate over serial, SSH, telnet.
* `find_lina_pid.py`: find the lina PID using SSH commands
* `template_gdbinit`: gdbinit template patched by `asadbg.py` for every targets
  we debug

## Requirements

* Python3 only
* Heavily tested on Linux (but could work on OS X to)
* Preloaded firmware on the flash of real ASA device or ASA emulator configured
  in GNS3

You initially need to modify `asadbg/env.sh` to match your environment. It will
allow you to define paths to the tools used by all the scripts as well as some
variables matching your ASA environment. Note there is a simmilar 
`asafw/env.sh` but only one is required to be used for both projects. We 
recommend that you add it to your `~/.bashrc`:

```
source /path/to/asadbg/env.sh
```

# Automated debugging

One of the main benefits of using asadbg is that you can automate your use of
both emulated (GNS3) and real Cisco ASA devices. This can include just
generally automating booting and running various firmwares and configs, or
specifically automating the debugging process of `lina` using gdb. This is mostly
done through the `asadbg.py` script. The main idea is to preload some flash on
the ASA device with firmware and configuration files that you want to use on
the device. For each firmware that you want to debug, you can use something
like the `asafw` tool to mine different symbols and then you can automatically
generate gdbinit files using those symbols. By default `asadbg.py` will use a
file `template_gdbinit` to automate building a version-specific gdbinit file at
runtime using whatever symbols are present in the database. 

## Quickly boot a real device (no debugging)

You can quickly boot a given version by specifying the firmware and configuration
files which must already be on the CF card.

```
asadbg.py --firmware asa802-k8.bin --config config-802
```

## Debugging a GNS3 device with config file

The following example shows how you can setup the configuration files to debug
a GNS3 device. First we define an `asadbg.cfg` configuration file similar to
below. It contains the GNS3 IP/port for the configured firewall that we obtain
from GSN3 itself.

```ini
[GLOBAL]
gns3_host=192.168.5.1
asadb_file=asadb.json

[asav941200]
version=941200
arch=gns3
rootfs_path= /home/user/_asav941-200.qcow2.extracted/rootfs
gns3_port=12005
attach_gdb=yes
```

It also points to the ASA database `asadb.json` file containing the addresses required. What 
is important here is that the `version=941200` and `arch=gns3` specified in
`asadbg.cfg` allow to match the firmware in `asadb.json` below. Also we indicate
we want to attach gdb.

```json
{
    "ASLR": false, 
    "addresses": {
        "clock_interval": 59514112, 
        "socks_proxy_server_start": 22139744, 
        "aaa_admin_authenticate": 418288
    }, 
    "fw": "asav941-200.qcow2", 
    "imagebase": 4194304,
    "version": "9.4.1.200",
    "arch": 64
}
```

Now we start debugging and `clock_interval` will be automatically patched:

```
asadbg$ ./asadbg.py --name asav941200 --asadbg-config asadbg.cfg
[asadbg] Using config file: asadbg.cfg
[asadbg] Found section: 'asav941200' in config
[asadbg] Using gdb: '/usr/bin/gdb'
[asadbg] Using architecture: gns3
[asadbg] Trying lina: /home/user/_asav941-200.qcow2.extracted/rootfs/asa/bin/lina
[asadbg] Going to debug...
[asadbg] Using GNS3 emulator 192.168.5.1:12005
[asadbg] Starting gdb now...
[gdbinit_941200] Configuring paths...
[gdbinit_941200] Disabling pagination...
[gdbinit_941200] Connecting over TCP/IP...
0x0000003655201190 in ?? () from /home/user/_asav941-200.qcow2.extracted/rootfs/lib64/ld-linux-x86-64.so.2
[gdbinit_941200] Connected.
[gdbinit_941200] Watchdog disabled
[gdbinit_941200] heap debugging plugins loaded
[gdbinit_941200] Additional gdb scripts loaded
[gdbinit_941200] Done.
(gdb) c
Continuing.
```

## Debugging a real device with config file

The following example shows how you can setup the configuration files to debug
a real Cisco ASA device over a serial console.

```ini
[GLOBAL]
serial_port=/dev/ttyUSB0
asadb_file=asadb.json

[asa924-gdb]
version=924
arch=32
rootfs_path=/home/user/_asa924-k8.bin.extracted/rootfs
firmware=asa924-k8-debugshell-gdbserver.bin
config=config-924
firmware_type=gdb
attach_gdb=yes
```

Note also that we need to specify a `firmware_type` which indicates if the 
firmware is unmodified, rooted or if gdb has been enabled at boot. This is
because we will do different things at boot depending on the format. Here we 
can see that we use a modified firmware `asa924-k8-debugshell-gdbserver.bin`
which has gdbserver enabled at boot and contains a debug shell. 
We see below that when the bootrom starts, asadbg automatically
interrupts the sequence in order to load the firmware and config files already 
on the CF card.

```
asadbg$ ./asadbg.py --name asa924-gdb --asadbg-config asadbg.cfg
[asadbg] Using config file: asadbg.cfg
[asadbg] Found section: 'asa924-gdb' in config
[asadbg] Using gdb: '/usr/bin/gdb'
[asadbg] Using architecture: 32
[asadbg] Trying lina: /home/user/_asa924-k8.bin.extracted/rootfs/asa/bin/lina
[asadbg] Going to debug...
[asadbg] Using serial port: /dev/ttyUSB0
[asadbg] Loading 'asa924-k8-debugshell-gdbserver.bin' with 'config-924'...
[comm] Waiting boot...
[SNIP]
Platform ASA5505

Use BREAK or ESC to interrupt boot.
Use SPACE to begin boot immediately.
Boot interrupted.

[SNIP]
rommon #0> boot asa924-k8-debugshell-gdbserver.bin cfg=config-924
Launching BootLoader...
Boot configuration file contains 1 entry.

Loading asa924-k8-debugshell-gdbserver.bin........ Booting...
Platform ASA5505
[SNIP]
SMFW PID: 514, Starting /asa/bin/lina under gdbserver /dev/ttyS0
SMFW PID: 512, started gdbserver on member: 514//asa/bin/lina
SMFW PID: 512, created member ASA BLOB, PID=514
Process /asa/bin/lina created; pid = 517
Remote debugging using /dev/ttyS0
[comm] gdb detected - boot finished.
[comm] Boot should be finished now?
[asadbg] Starting gdb now...
[gdbinit_924] Configuring paths...
[gdbinit_924] Disabling pagination...
[gdbinit_924] Connecting over USB...
0xdc7e2820 in ?? () from /home/user/_asa924-k8.bin.extracted/rootfs/lib/ld-linux.so.2
[gdbinit_924] Connected.
[gdbinit_924] Watchdog disabled
[gdbinit_924] heap debugging plugins loaded
[gdbinit_924] Additional gdb scripts loaded
[gdbinit_924] Done.
(gdb) c
Continuing.
```

# Importing additional symbols

Numerous parts of asadbg rely on a database `asadbg/asadb.json` that
contains symbols for various firmware versions. We have supplied a small
number of existing symbols, however you can add others manually or use 
[idahunt](https://github.com/nccgroup/idahunt)
to automatically add new targets. This section details how to do it.

## Requirements

The IDA Python scripts in asadbg assume that `filelock.py/ida_helper.py` are 
available. Since they are executed directly from IDA Python, the way we have 
done it so far is by creating symlinks in `asadbg/`. We can’t really create them 
on the repo as the symlinks on Windows are different than on Linux. Consequently 
it is required to do manually.
 
On Linux:

```
asadbg$ ln -s ../idahunt/ida_helper.py ida_helper.py
asadbg$ ln -s ../idahunt/filelock.py filelock.py
```

On Windows, with Administrator permissions:

```
C:\asadbg> mklink filelock.py ..\idahunt\filelock.py
C:\asadbg> mklink ida_helper.py ..\idahunt\ida_helper.py
```

We also need to set the path to the database (automatically done by `env.sh`):

```
C:\idahunt>set ASADBG_DB=C:\asadbg\asadb.json
```

## Initial analysis and renaming

We assume you have extracted all the firmware into a directory using e.g. 
[asafw](https://github.com/nccgroup/asafw) or that you
extracted only the `lina` files and dropped them into a hierarchy that indicates
what firmware they come from:

```
C:\temp>tree /F
Folder PATH listing
Volume serial number is XXXX-XXX
C:.
├───asa924-k8.bin
│       lina
│
├───asa924-smp-k8.bin
│       lina
│
└───asav941-200.qcow2
        lina
```

First you need to do the initial analysis in IDA. We can use `--list-only` with
any command to check what would be the result of the command.

Note we filter to specific ASA versions (9.2.4) and architecture (32-bit):

```
C:\idahunt>idahunt.py --verbose --inputdir "C:\temp" --analyse --scripts C:\asadbg\asadbg_rename.py --filter "filters\ciscoasa.py -m 924 -M 924 -v -a 32"
[idahunt] IDA32 = C:\Program Files (x86)\IDA 6.95\idaq.exe
[idahunt] IDA64 = C:\Program Files (x86)\IDA 6.95\idaq64.exe
[idahunt] ANALYSING FILES
[idahunt] Analysing C:\temp\asa924-k8.bin\lina
[idahunt] C:\Program Files (x86)\IDA 6.95\idaq.exe -B -LC:\temp\asa924-k8.bin\lina.log C:\temp\asa924-k8.bin\lina
[ciscoasa] Skipping non 32-bit: C:\temp\asa924-smp-k8.bin\lina
[ciscoasa] Skipping version too high: C:\temp\asav941-200.qcow2\lina
[idahunt] Waiting on remaining 1 IDA instances

[idahunt] EXECUTE SCRIPTS
[idahunt] Executing script C:\asadbg\asadbg_rename.py for C:\temp\asa924-k8.bin\lina
[idahunt] C:\Program Files (x86)\IDA 6.95\idaq.exe -A -SC:\asadbg\asadbg_rename.py -LC:\temp\asa924-k8.bin\lina.log C:\temp\asa924-k8.bin\lina.idb
[ciscoasa] Skipping non 32-bit: C:\temp\asa924-smp-k8.bin\lina
[ciscoasa] Skipping version too high: C:\temp\asav941-200.qcow2\lina
[idahunt] Waiting on remaining 0 IDA instances
```

Once the analysis is done, you should have a `lina.i64` or `lina.idb` near `lina`
in the respective folders.

## Adding symbols to the database

We use idahunt to add symbols to the database:

```
C:\idahunt>idahunt.py --verbose --inputdir "C:\temp" --scripts C:\asadbg\asadbg_hunt.py --filter "filters\ciscoasa.py -v"
[idahunt] IDA32 = C:\Program Files (x86)\IDA 6.95\idaq.exe
[idahunt] IDA64 = C:\Program Files (x86)\IDA 6.95\idaq64.exe
[idahunt] EXECUTE SCRIPTS
[idahunt] Executing script C:\asadbg\asadbg_hunt.py for C:\temp\asa924-k8.bin\lina
[idahunt] C:\Program Files (x86)\IDA 6.95\idaq.exe -A -SC:\asadbg\asadbg_hunt.py -LC:\temp\asa924-k8.bin\lina.log C:\temp\asa924-k8.bin\lina.idb
[idahunt] Executing script C:\asadbg\asadbg_hunt.py for C:\temp\asa924-smp-k8.bin\lina
[idahunt] C:\Program Files (x86)\IDA 6.95\idaq64.exe -A -SC:\asadbg\asadbg_hunt.py -LC:\temp\asa924-smp-k8.bin\lina.log C:\temp\asa924-smp-k8.bin\lina.i64
[idahunt] Executing script C:\asadbg\asadbg_hunt.py for C:\temp\asav941-200.qcow2\lina
[idahunt] C:\Program Files (x86)\IDA 6.95\idaq64.exe -A -SC:\asadbg\asadbg_hunt.py -LC:\temp\asav941-200.qcow2\lina.log C:\temp\asav941-200.qcow2\lina.i64
[idahunt] Executing script C:\asadbg\asadbg_hunt.py for C:\temp\asav962-7.qcow2\lina
[idahunt] C:\Program Files (x86)\IDA 6.95\idaq64.exe -A -SC:\asadbg\asadbg_hunt.py -LC:\temp\asav962-7.qcow2\lina.log C:\temp\asav962-7.qcow2\lina.i64
[idahunt] Waiting on remaining 0 IDA instances
```

# Automating executing commands on the CLI

We support executing some useful commands automatically using either SSH, the serial
and theoretically support telnet as well though it has not been heavily tested.

```
$ comm.py -h
usage: comm.py [-h] [--comm COMM_TYPE] [--port TARGET_PORT] [--ip TARGET_IP]
               [--user USER] [--pass PASSWORD] [--reboot] [--version]
               [--disable-checkheaps] [--upload] [--force] [--download]
               [--delete-ike-sa] [--delete-webvpn-sessions] [--md5]
               [--input [INPUT [INPUT ...]]] [--oldssh] [--cmd CMD]
               [-C CFG_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --comm COMM_TYPE      Communication type {serial(default), telnet, ssh}
  --port TARGET_PORT    Specify a custom serial (e.g. "/dev/ttyUSB0")/telnet
                        (e.g. 5000) port)
  --ip TARGET_IP        Cisco ASA/GNS3 IP address
  --user USER           User for SSH
  --pass PASSWORD       Password for SSH
  --reboot              Reboot router (serial, SSH)
  --version             Get the version (serial, SSH)
  --disable-checkheaps  Disable checkheaps default timeout (60 sec)
  --upload              Upload over SSH
  --force               Overwrite existing files
  --download            Download over SSH
  --delete-ike-sa       Delete IKE SAs (serial, SSH)
  --delete-webvpn-sessions
                        Delete WebVPN sessions (serial, SSH)
  --md5                 Compute MD5 for files (serial, SSH)
  --input [INPUT [INPUT ...]]
                        List of input files for other commands (eg: file1
                        file2 file3) (e.g.: --upload, --download, --md5)
  --oldssh              Specify an old version of SSH (do not know specific
                        command lines options and do not need them because
                        unsecure :))
  --cmd CMD             Command to run on the CLI (debugging)
  -C CFG_FILE           File containing commands to use (e.g.
                        config/setup_ssh.cfg)
```

## Getting the ASA version

We use `--version` and can execute it over serial or SSH:

```
$ comm.py --comm serial --port /dev/ttyUSB0 --version
[comm] Retrieving version now...
[comm] Serial: /dev/ttyUSB0
[comm] Detected version: 9.2(4)
$ comm.py --comm ssh --ip 192.168.210.77 --port 22 --user user --pass user --version
[comm] Retrieving version now...
[comm] SSH: 192.168.210.77:22
[comm] Detected version: 9.2(4)
```

## Rebooting the ASA

We use `--reboot`:

```
$ comm.py --comm ssh --reboot
[comm] Rebooting router now...
[comm] SSH: 192.168.210.77:22
```

if you have a running CLI, you should see it automatically reboots:

```
ciscoasa#  

***
*** --- START GRACEFUL SHUTDOWN ---
Shutting down isakmp
Shutting down License Controller
Shutting down File system

***
*** --- SHUTDOWN NOW ---
Process shutdown finished
```

## Uploading files to the flash

We can upload several files at a time over SSH:

```
$ comm.py --upload --comm ssh --oldssh --pass user --input fw/*
[comm] Warning: using forced SSH
[comm] Uploading file...
[comm] SSH: 192.168.210.77:22
[comm] Uploading: asa924-5-k8.bin...
[comm] Executing 'sshpass -p user scp  fw/asa924-5-k8.bin user@192.168.210.77:asa924-5-k8.bin'...
Connection to 192.168.210.77 closed by remote host.
[comm] Uploading file...
[comm] SSH: 192.168.210.77:22
[comm] Uploading: asa924-k8.bin...
[comm] Executing 'sshpass -p user scp  fw/asa924-k8.bin user@192.168.210.77:asa924-k8.bin'...
Connection to 192.168.210.77 closed by remote host.
[comm] Finished all tasks.
```

Note that `--oldssh` is useful if you are using an old ssh client.

## Computing MD5 of files on the flash

It is sometimes useful to check the MD5 of files on the flash to make sure
the files have been correctly uploaded.

```
$ comm.py --md5 --input asa924-k8.bin asa924-5-k8.bin --comm ssh
Calculating MD5. Will take 20 seconds... asa924-k8.bin = 4558b27d0dd7ba1751e43b0ba33593a3
Calculating MD5. Will take 20 seconds... asa924-5-k8.bin = 74765d62abb2c4a5e677ed9ca49ebf87
```

# Determining the lina PID/memory mapping in gdb

By default, gdb does not know the lina PID.

```
(gdb) info proc mappings
Can't determine the current process's PID: you must name one.
```

We use `find_lina_pid.py` to find the lina PID.
Then we use `info proc mappings <pid>` to get the mapping.

```
(gdb) source find_lina_pid.py 
Finding lina PID:
516
You can use the following to see the lina mapping: info proc mappings <pid>
(gdb) info proc mappings 516
process 516
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0xa388000  0x2340000        0x0 /asa/bin/lina
	 0xa388000  0xa38a000     0x2000  0x233f000 /asa/bin/lina
	 0xa38a000  0xa9aa000   0x620000  0x2341000 /asa/bin/lina
	 0xa9aa000  0xb74b000   0xda1000  0xa9aa000 [heap]
	0xa5ad9000 0xa5bda000   0x101000 0xa5ad9000 
	0xa5bda000 0xa5bde000     0x4000        0x0 /dev/zero (deleted)
	0xa5bde000 0xa5de1000   0x203000 0xa5bde000 
	0xa5de1000 0xa5de5000     0x4000 0x50004000 /dev/mem
	0xa5de5000 0xa5fe7000   0x202000 0xa5de5000 
	0xa5fe7000 0xa5fe8000     0x1000 0xffb00000 /dev/mem
	0xa5fe8000 0xa5ff8000    0x10000 0xfff00000 /dev/mem
	0xa5ff8000 0xa6000000     0x8000    0xd8000 /dev/mem
	0xa6000000 0xa8724000  0x2724000        0x0 /dev/udma0
	0xa8800000 0xab400000  0x2c00000        0x0 /SYSV00000002 (deleted)
	0xab400000 0xab800000   0x400000  0x2c00000 /SYSV00000002 (deleted)
	0xab800000 0xabc00000   0x400000  0x3000000 /SYSV00000002 (deleted)
	0xabc00000 0xac000000   0x400000  0x3400000 /SYSV00000002 (deleted)
	0xac000000 0xac400000   0x400000  0x3800000 /SYSV00000002 (deleted)
	0xac400000 0xdbc00000 0x2f800000  0x3c00000 /SYSV00000002 (deleted)
	0xdbf55000 0xdbf58000     0x3000 0xdbf55000 
	0xdbf58000 0xdc091000   0x139000        0x0 /lib/libc-2.9.so
	0xdc091000 0xdc092000     0x1000   0x139000 /lib/libc-2.9.so
	0xdc092000 0xdc094000     0x2000   0x139000 /lib/libc-2.9.so
	0xdc094000 0xdc095000     0x1000   0x13b000 /lib/libc-2.9.so
	0xdc095000 0xdc098000     0x3000 0xdc095000 
	0xdc098000 0xdc0a2000     0xa000        0x0 /lib/libgcc_s.so.1
	0xdc0a2000 0xdc0a3000     0x1000     0x9000 /lib/libgcc_s.so.1
	0xdc0a3000 0xdc0a4000     0x1000     0xa000 /lib/libgcc_s.so.1
	0xdc0a4000 0xdc0c8000    0x24000        0x0 /lib/libm-2.9.so
	0xdc0c8000 0xdc0c9000     0x1000    0x23000 /lib/libm-2.9.so
	0xdc0c9000 0xdc0ca000     0x1000    0x24000 /lib/libm-2.9.so
	0xdc0ca000 0xdc0d3000     0x9000        0x0 /lib/libudev.so.0.5.0
	0xdc0d3000 0xdc0d4000     0x1000     0x8000 /lib/libudev.so.0.5.0
	0xdcfeb000 0xdd000000    0x15000 0xdcfeb000 [stack]
	0xffffe000 0xfffff000     0x1000        0x0 [vdso]
	0xdc0e0000 0xdc0e1000     0x1000     0xa000 /usr/lib/libcgroup.so.1.0.34
	0xdc0e1000 0xdc0e2000     0x1000     0xb000 /usr/lib/libcgroup.so.1.0.34
	0xdc0e2000 0xdc6dc000   0x5fa000 0xdc0e2000 
	0xdc6dc000 0xdc6e3000     0x7000        0x0 /lib/librt-2.9.so
	0xdc6e3000 0xdc6e4000     0x1000     0x6000 /lib/librt-2.9.so
	0xdc6e4000 0xdc6e5000     0x1000     0x7000 /lib/librt-2.9.so
	0xdc6e5000 0xdc6e7000     0x2000        0x0 /lib/libdl-2.9.so
	0xdc6e7000 0xdc6e8000     0x1000     0x1000 /lib/libdl-2.9.so
	0xdc6e8000 0xdc6e9000     0x1000     0x2000 /lib/libdl-2.9.so
	0xdc6e9000 0xdc6fd000    0x14000        0x0 /lib/libpthread-2.9.so
	0xdc6fd000 0xdc6fe000     0x1000    0x13000 /lib/libpthread-2.9.so
	0xdc6fe000 0xdc6ff000     0x1000    0x14000 /lib/libpthread-2.9.so
	0xdc6ff000 0xdc701000     0x2000 0xdc6ff000 
	0xdc701000 0xdc71c000    0x1b000        0x0 /usr/lib/libexpat.so.1.6.0
	0xdc71c000 0xdc71e000     0x2000    0x1a000 /usr/lib/libexpat.so.1.6.0
	0xdc71e000 0xdc71f000     0x1000    0x1c000 /usr/lib/libexpat.so.1.6.0
	0xdc71f000 0xdc7cd000    0xae000        0x0 /lib/libstdc++.so.6.0.10
	0xdc7cd000 0xdc7d1000     0x4000    0xad000 /lib/libstdc++.so.6.0.10
	0xdc7d1000 0xdc7d2000     0x1000    0xb1000 /lib/libstdc++.so.6.0.10
	0xdc7d2000 0xdc7d8000     0x6000 0xdc7d2000 
	0xdc7d8000 0xdc7dd000     0x5000        0x0 /usr/lib/libnuma.so.1
	0xdc7dd000 0xdc7de000     0x1000     0x4000 /usr/lib/libnuma.so.1
	0xdc7de000 0xdc7df000     0x1000     0x5000 /usr/lib/libnuma.so.1
	0xdc7df000 0xdc7e0000     0x1000 0xdc7df000 
	0xdc7e1000 0xdc7e2000     0x1000 0xdc7e1000 
	0xdc7e2000 0xdc7fe000    0x1c000        0x0 /lib/ld-2.9.so
	0xdc7fe000 0xdc7ff000     0x1000    0x1b000 /lib/ld-2.9.so
	0xdc7ff000 0xdc800000     0x1000    0x1c000 /lib/ld-2.9.so
	0xdcfeb000 0xdd000000    0x15000 0xdcfeb000 [stack]
	0xffffe000 0xfffff000     0x1000        0x0 [vdso]
```
