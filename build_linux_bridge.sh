#!/bin/sh
#
# This file is part of asadbg.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# This script is designed to setup an Ubuntu host with a bridged ethernet
# device that can be used to talk to a Cisco firmware running on GNS3/qemu
#
# TODO: 
#  - Make sure all commands are installed exit

usage()
{
    echo "Usage:"
    echo "-a  Addr range - By default uses br0"
    echo "-b  Bridge interface - By default uses 192.168.100.1/24"
    echo "-i  Host ethernet interface - By default uses eno2"
    echo "-k  Kill the devices we've created"
    echo "-g  Default gateway - By default uses 192.168.100.1"
    echo "-t  Tap interface - By default uses tap2"
    echo "./build_linux_bridge.sh -i <interface> -t <tap name> -b <bridge name>"
    echo ""
    echo "NOTE: If cmds fail: apt-get install uml-utilities bridge-utils"
    exit
}

if [ "$(whoami)" != "root" ]; then
    echo "Run me as root"
    exit
fi

IFACE="eno2"
 # IMPORTANT: Avoid tap0 if you are using a VPN
TAP="tap2"
BR="br0"
DUMMY_ADDR="192.168.100.254/24"
BRIDGE_ADDR="192.168.100.1/24"
GW="192.168.100.1"

KILL="NO"
while [ $# -gt 0 ]
do
    key="$1"

    case $key in
        -a|--bridge-addr)
        BRIDGE_ADDR="$2"
        shift # past argument
        ;;
        -b|--bridge)
        BR="$2"
        shift # past argument
        ;;
        -d|--dummy-addr)
        DUMMY_ADDR="$2"
        shift # past argument
        ;;
        -g|--gateway)
        GW="$2"
        shift # past argument
        ;;
        -i|--interface)
        IFACE="$2"
        shift # past argument
        ;;
        -k|--kill)
        KILL="YES"
        ;;
        -t|--tap)
        TAP="$2"
        shift # past argument
        ;;
        *)
        # unknown option
        echo "Unknown option"
        usage
        ;;
    esac
    shift # past argument or value
done

if [ "${KILL}" != "NO" ]; then
#    echo "Deleting route"
    route del default gw ${GW}
    echo "Tearing down ${BR}"
    ifconfig ${BR} down
    brctl delbr ${BR}
    echo "Deleting TAP ${TAP}"
    tunctl -d ${TAP}
#    ip addr del ${DUMMY_ADDR} brd + dev ${IFACE} label ${IFACE}:0
    ip addr del ${DUMMY_ADDR} dev ${IFACE}
    ip link delete ${IFACE} type dummy
    # We don't unload dummy or tun incase it they were already in use
    exit
fi

echo "Loading tun module"
modprobe tun

echo "Loading dummy module"
modprobe dummy
if [ $? != 0 ]; then
    echo "Couldn't load the dummy module need for virtual interface"
fi
echo "Creating dummy interface"
ip link add dummy0 type dummy
ip link set name ${IFACE} dev dummy0

echo "Creating tap device ${TAP}"
tunctl -t ${TAP}

ifconfig ${TAP} 0.0.0.0 promisc up
ifconfig ${IFACE} 0.0.0.0 promisc up

echo "Creating bridge device ${BR}"
brctl addbr ${BR}
brctl show ${BR}

ifconfig ${IFACE} up 
echo "Assocating ${IFACE} and ${TAP} to ${BR}"
brctl addif ${BR} ${IFACE}
brctl addif ${BR} ${TAP}
echo "Bringing up bridge"
ifconfig ${BR} up
sleep 1
echo "Setting ${BR} addr to ${BRIDGE_ADDR}"
ifconfig ${BR} ${BRIDGE_ADDR}
echo "Setting ${IFACE} addr to ${DUMMY_ADDR}"
ip addr add ${DUMMY_ADDR} dev ${IFACE}
echo "Setting default route"
ip route add 192.168.100.0/24 dev ${TAP}

echo "All done."
echo "You can tear the network down with --kill"
