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

    def scan_menu(self,scanner,ports):
        if scanner == scan_list[0]:
            Scan.TPC_sS(ports)
        elif scanner == scan_list[1]:
            Scan.TCP_sX(ports,"FPU")
        elif scanner == scan_list[2]:
            Scan.TCP_sX(ports,"")
        elif scanner == scan_list[3]:
            Scan.UDP_U(ports)

    def TPC_sS(self,ports):
        for self.port in ports:
            # src_port=RandShort()
            packet = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=self.port,flags="S"),timeout=0.05,verbose=0)

            if (packet.haslayer(TCP)) and (packet.getlayer(TCP).flags == 0x12):
                send_rst = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=self.port,flags="R"),timeout=0.05,verbose=0)
                print(str(self.port)+"/tpc \t Open")


    def TCP_sX(self,ports,flaging):

        for self.port in ports:

            packet = sr1(IP(dst=dst_ip) / TCP(sport=src_port,dport=self.port, flags=flaging), timeout=0.001,verbose=0)

            # print(packet[TCP].flag=="<class 'NoneType'>")

            if (str(type(packet)) == "<class 'NoneType'>"):
                print(str(self.port)+"/tpc \t Open|Filtered")

            elif (packet.haslayer(ICMP)):
                if (int(packet.getlayer(ICMP).type) == 3 and int(packet.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    print(str(self.port) + "/tpc \t Filtered")

    def UDP_U(self, ports):


        for self.port in ports:

            packet = sr1(IP(dst=dst_ip) / UDP(sport=src_port,dport=self.port),timeout=10,verbose=0)

            # print(str(type(packet)))

            if (str(type(packet)) == "<class 'NoneType'>"):
                print(str(self.port) + "/UDP \t Open|Filtered")

            elif packet.haslayer(UDP):
                print(str(self.port) + "/UDP \t Open")

            elif (int(packet.getlayer(ICMP).type) == 3 and int(packet.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
                print(str(self.port) + "/UDP \t Filtered")

            # else:
            #     print(str(self.port) + "/UDP \t Closed")

def UserInterp():
    while True:
        print("Enter a valid Scan: " + str(scan_list))
        scan_choice=input("Enter the interface: ")

        if scan_choice in list(scan_list):
            while True:

                try:
                    min_P = int(input("Enter Valid min port number: "))
                    max_P = int(input("Enter Valid max port number: "))
                    if (min_P)>0 and (min_P)<(max_P) and (min_P)<65536:
                        break
                except:
                    continue

            break

    return scan_choice,[ x for x in range(min_P, max_P) ]

Scan=Port_Scan()
scan_list = ("TPC_sS", "TCP_sX", 'TPC_null','UDP_U')





def main():
    SC,ports=UserInterp()
    Scan.scan_menu(SC,ports)




if __name__== "__main__":  # initilising
    main()