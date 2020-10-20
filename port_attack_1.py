#! /usr/bin/python
from scapy.all import *

# This script performs Port scan attacks.

dst_ip = "10.0.2.19"  # metasploitable victim to port scanning
src_port = RandShort()  # Random source port

# Class for Port scan attacks 
# TCP stealth (sS), 2 TCP XMAS (sX), 3 TCP Null (sN) and 4 UDP (sU) scans.
class Port_Scan:

    def scan_menu(self,scanner,ports,scan_list):  # parsing the user entry for the type of port scan
        if scanner == scan_list[0]:
            Scan.TCP_sS(ports)
        elif scanner == scan_list[1]:
            Scan.TCP_sX_sN(ports,"FPU")
        elif scanner == scan_list[2]:
            Scan.TCP_sX_sN(ports,"")
        elif scanner == scan_list[3]:
            Scan.UDP_U(ports)

    def TCP_sS(self,ports):  # performing TPC stealth scan
        for self.port in ports:  # Looping for all ports in the range of user entry

            try:
                packet = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=self.port,flags="S"),timeout=3,verbose=0)
            except Exception as e:
                print(e)

            if (packet.haslayer(TCP)) and (packet.getlayer(TCP).flags == 0x12):  # if TCP layer and ACK-SYN flag
                # Sending a RST back to the victim port to stop communication.
                try:
                    send_rst = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=self.port,flags="R"),timeout=3,verbose=0)
                except Exception as e:
                    print(e)
                print(str(self.port)+"/tpc \t Open")


    def TCP_sX_sN(self,ports,flaging): # performing TPC sX or sN

        for self.port in ports:
            # sending a TPC packet with either a FPU or Null flag
            try:
                packet = sr1(IP(dst=dst_ip) / TCP(sport=src_port,dport=self.port, flags=flaging), timeout=10,verbose=0)
            except Exception as e:
                print(e)

            if (str(type(packet)) == "<class 'NoneType'>"):
                print(str(self.port)+"/tpc \t Open|Filtered")

            elif (packet.haslayer(ICMP)):
                if (int(packet.getlayer(ICMP).type) == 3 and int(packet.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    print(str(self.port) + "/tpc \t Filtered")

    def UDP_U(self, ports):  # performing UDP sU
        for self.port in ports:

            # Sending a udp paket
            try:
                packet = sr1(IP(dst=dst_ip) / UDP(sport=src_port,dport=self.port),timeout=10,verbose=0)
            except Exception as e:
                print(e)

            if (str(type(packet)) == "<class 'NoneType'>"):
                print(str(self.port) + "/UDP \t Open|Filtered")  # when no response port is open|filtered

            elif packet.haslayer(UDP):
                print(str(self.port) + "/UDP \t Open")  # UDP received back

            elif (int(packet.getlayer(ICMP).type) == 3 and int(packet.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
                print(str(self.port) + "/UDP \t Filtered")  # ICMP packet returned


def UserInterp(scan_list):
    while True:  # loop until valid scan technique is chosen
        print("Enter a valid Scan: " + str(scan_list))  # showing the user which are the options
        scan_choice=input("Enter the scan method: ")

        if scan_choice in list(scan_list):  # if there was a valid entry
            while True:

                try:
                    min_P = int(input("Enter Valid min port number: "))  # bottom of the range
                    max_P = int(input("Enter Valid max port number: "))  # top of the range
                    if (min_P)>0 and (min_P)<(max_P) and (min_P)<65536:  # checking validity
                        break
                    else:
                        print("0 < min port < max port < 65536")
                except:  # if there is an unexpected error continue.
                    continue

            break

    return scan_choice,[ x for x in range(min_P, max_P) ]  # returning scan method and port range to attack

Scan = Port_Scan()  # initialising port scan attack
def main():
    scan_list = ("TCP_sS", "TCP_sX", 'TCP_sN', 'UDP_U')
    SC,ports=UserInterp(scan_list)
    Scan.scan_menu(SC,ports,scan_list)  # Outputting the open ports

if __name__== "__main__":  # initialising
    main()