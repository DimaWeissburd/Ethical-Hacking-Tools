#!/usr/bin/env python

# Usage example: python 02_network_scan.py --t *.*.*.*/24

import argparse
from scapy.all import Ether, ARP, srp

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--t', dest='target', required=True)
    args = parser.parse_args()
    return args

def scan(ip):
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = ARP(pdst=ip)
    answered_list = srp(broadcast/arp_request, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        clients_list.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return clients_list

def print_scan(clients_list):
    print("IP\t\t\tMAC Address\n------------------------------------------")
    for client in clients_list:
        print (client["ip"] + "\t\t" + client["mac"])

args = get_arguments()
clients_list = scan(args.target)
print_scan(clients_list)