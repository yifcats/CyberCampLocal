#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "10.0.2.19"
src_port = RandShort()



Open_Port=[]

class Port_Scan:
    def __init__(self):
        self.tcpPorts = [ x for x in range(0, 65536) ]

    def TPC_sS(self):
        for self.port in self.tcpPorts:
            packet = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=self.port,flags="S"),timeout=0.1,verbose=0)

            if (packet.haslayer(TCP)) and (packet.getlayer(TCP).flags == 0x12):
                send_rst = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=self.port,flags="R"),timeout=0.1,verbose=0)
                print(str(self.port)+"/tpc \t Open")



    def TPC_sX(self):

        for self.port in self.tcpPorts:

            packet = sr1(IP(dst=dst_ip) / TCP(dport=self.port, flags="FPU"), timeout=10,verbose=0)

            if (str(type(packet)) == "<type 'NoneType'>"):
                print(str(self.port)+"/tpc \t Open|Filtered")
            elif (packet.haslayer(TCP)) and (packet.getlayer(TCP).flags == 0x14):
                print(str(self.port) + "/tpc \t Closed")
            elif (packet.haslayer(ICMP)):
                if (int(packet.getlayer(ICMP).type) == 3 and int(packet.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    print(str(self.port) + "/tpc \t Filtered")


def UserInterp():
    scan_list=("TPC_sS","TPC_sX")
    while True:
        print("Enter a valid Scan: " + str(scan_list))
        scan_choice=input("Enter the interface: ")

        if scan_choice in list(scan_list):
            break

    return scan_choice

Scan=Port_Scan()

def main():
    SC=UserInterp()
    if SC == 'TPC_sS':
        Scan.TPC_sS()
    elif SC == 'TPC_sX':
        Scan.TPC_sX()



if __name__== "__main__":  # initilising
    main()