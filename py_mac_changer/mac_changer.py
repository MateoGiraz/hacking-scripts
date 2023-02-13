#!/usr/bin/env python3

import subprocess
import optparse


def change_mac(interface, newmac):
    print("[+] Changing MAC adress for " + interface + " to " + newmac)

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", newmac])
    subprocess.call(["ifconfig", interface, "up"])


def get_arguments():

    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="interface to change MACs adress")
    parser.add_option("-m", "--MAC", dest="newMAC", help="new MAC adress")
    return parser.parse_args()


(options, arguments) = get_arguments()
change_mac(options.interface, options.newMAC)

result = subprocess.check_output("ifconfig")
if options.newMAC in str(result):
    print("MAC adress changed to: "+options.newMAC)
else:
    print("failed to change MAC adress")
