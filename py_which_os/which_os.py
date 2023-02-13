#!/usr/bin/python3

import re, sys, subprocess

class bcolors:
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    FAIL = '\033[91m'


def get_ttl(ip):
        proc = subprocess.Popen(["/usr/bin/ping -c 1 %s 2>/dev/null" % ip, ""], stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        out = (out.split()[12]).decode("utf-8")
        ttl_value = re.findall(r"\d{1,3}", out)[0]
        return ttl_value


def getOs(ttl):
        ttl = int(ttl)
        if ttl >= 0 and ttl <= 64:
                return "Linux"
        elif ttl > 64 and ttl <= 128:
                return "Windows"
        else:
                return "Not found"


if len(sys.argv) != 2:
        print(bcolors.FAIL + "\n[!] Use: python3 " + sys.argv[0] + " <ip_adress>\n" + bcolors.ENDC)
        sys.exit(1)
else:
        try:
                ip_adress = sys.argv[1]
                ttl = get_ttl(ip_adress)
                os = getOs(ttl)
                print(bcolors.BLUE + "\n IP  ->  %s \n ttl ->  %s \n OS  ->  %s\n" % (ip_adress, ttl, os) + bcolors.ENDC)
        except:
                print("\nInput " + sys.argv[1] + bcolors.FAIL + " is not a valid IP adress \n\n[!] Use: python3 " + sys.argv[0] + " <ip_adress>\n" + bcolors.ENDC)

