#!/usr/bin/python3
from sys import stdout
from scapy.all import *
from random import randint
from argparse import ArgumentParser

list=[1]

print(list[-1])

# packet=IP(dst="37.202.5.70",src=RandIP("192.168.1.246/24")) / TCP(dport=80,sport=RandShort(),flags="S")

packet=IP(dst="10.0.2.19") / TCP(dport=80,sport=RandShort(),flags="S")
srloop(packet)
