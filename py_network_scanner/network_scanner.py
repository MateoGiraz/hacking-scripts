#!/usr/bin/env python

import scapy.all as scapy
import optparse


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]
    clients_list = []
    for element in answered:
        client_dic={"ip":element[1].psrc, "mac":element[1].hwsrc}
        clients_list.append(client_dic)
    return clients_list


def show(list):
    print("IP\t\tMAC")
    print("---------------------------------")
    for element in list:
        print(element["ip"]+"        "+element["mac"])


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="target IP / IP range")
    (options, arguments) = parser.parse_args()
    return options.ip


show(scan(get_arguments()))
