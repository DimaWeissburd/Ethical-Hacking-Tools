#!/usr/bin/env python

# Provide target interface and new mac address as arguments
# Usage example: python 01_linux_mac_change.py --i interface_name --m **:**:**:**:**:**

import subprocess
import argparse
import re

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--i', dest='interface', required=True)
    parser.add_argument('--m', dest='mac', required=True)
    args = parser.parse_args()
    if not (re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", args.mac)):
        parser.error("Wrong mac format.")
    return args

def linux_change_mac(interface, new_mac):
    subprocess.call(['ip', 'link', 'set', interface, 'down'])
    subprocess.call(['ip', 'link', 'set', interface, 'address', new_mac])
    subprocess.call(['ip', 'link', 'set', interface, 'up'])

def read_mac_address(interface):
    ip_result = subprocess.check_output(['ip', 'a', 'show', interface])
    return re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", str(ip_result)).group(0)

def validate_mac_change(current_mac, new_mac):
    if (current_mac):
        if (current_mac == new_mac):
            print('MAC address was successfully changed to ' + new_mac)
        else:
            print('Something went wrong, mac was not set to chosen value.')
    else:
        print('Could not read mac address from chosen interface.')

arguments = get_arguments()
linux_change_mac(arguments.interface, arguments.mac)
validate_mac_change(read_mac_address(arguments.interface), arguments.mac)
