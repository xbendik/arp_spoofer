#!usr/bin/env python
#run it in Python 3!

from scapy.layers import all as scapy

packet = scapy.ARP(op=2, pdst="192.168.1.2", hwdst="02:81:10:c0:00:42", psrc="192.168.1.1")