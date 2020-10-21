#! /usr/bin/python
from scapy.all import *
from scapy.layers.inet import TCP
import datetime
from time import sleep
import logging
from threading import Thread, Event


# This script is used to perform detection for SYN floods and port scan attacks.

# Function requesting user to Enter a valid Interface available from a list.
def which_interface():
    while True:
        print("Enter a valid Interface: " + str(get_if_list()))
        intface = input("Enter the interface: ")

        if intface in list(get_if_list()[:]):  # if the entry is valid break.
            break
    return intface  # Return the interface chosen by the user.


# The following is a class which is used to identify the occurrence of 2 attacks.
# 1. SYN Flood.
# 2. Port Scam Attacks of the form: 1 TCP stealth (sS), 2 TCP XMAS (sX), 3 TCP Null (sN) and 4 UDP (sU) scans.
# ALL TCP, UDP and ICMP protocols are logged in sniff1.log throughout communication.

class Identification(Thread):

    def __init__(self):
        super().__init__()  # Used to be able to run the sniffer from the class.
        self.daemon = True
        self.stop_sniffer = Event()

        self.Interface = which_interface()  # Calling the user for interface inputs.

        # Creating a character calls for all required Variables.
        self.s_com = Sorting_Packets()  # SYN Communication.
        self.sa_com = Sorting_Packets()  # ACK-SYN Communication.
        self.a_com = Sorting_Packets()  # ACK Communication.
        self.r_com = Sorting_Packets()  # RST-ACK Communication.
        self.fpu_com = Sorting_Packets()  # FIN-PSH_URG Communication.
        self.null_com = Sorting_Packets()  # Null (no flag) Communication.
        self.udp_com = Sorting_Packets()  # UDP Communication.
        self.icmp_com = Sorting_Packets()  # ICMP Communication.

        self.limit = 5  # triggering tool for SYN Flooding

    def run(self):  # Calling the function when initialising the class.
        sniff(iface=self.Interface, prn=self.packet_handler)  # sniffing all packets in the interface.

    def join(self, timeout=0):  # creating a stop for the sniffer
        self.stop_sniffer.set()
        super().join(timeout)
        return self.stop_sniffer.isSet()

    # Function which takes the paket sniffed as an input and sends data to the identification functions.
    # syn_detection and port_scan_detection
    def packet_handler(self, pkt):
        time = datetime.datetime.now()
        print_log(pkt, time)

        # Packets are differentiated using the following function based on layer and flags.
        self.s_com, self.sa_com, self.a_com, self.r_com, self.fpu_COM, \
        self.null_com, self.udp_com, self.icmp_com = self.pack_sorter(pkt)

        if pkt.haslayer(TCP):
            self.syn_detection(self.s_com, self.sa_com, self.a_com, time)  # SYN flood detection

        self.port_scan_detection(pkt, self.s_com, self.sa_com, self.a_com, self.r_com, \
                                 self.fpu_COM, self.null_com, self.udp_com, self.icmp_com, time)  # Port scan detection

    def pack_sorter(self, pkt):  # sorts the packets by layer and flags
        if pkt.haslayer(TCP):  # for TCP packets
            F = pkt['TCP'].flags
            if F == 0x02 and F != 0x10:  # SYN Communication.
                self.s_com.pack_data_TPC(pkt)  # filling in the instances

            elif F == 0x12:  # ACK-SYN Communication.
                self.sa_com.pack_data_TPC(pkt)  # filling in the instances

            elif F == 0x10:  # ACK Communication.
                self.a_com.pack_data_TPC(pkt)  # filling in the instances

            elif F == 0x14:  # RST-ACK Communication
                self.r_com.pack_data_TPC(pkt)  # filling in the instances

            elif F == 0x29:  # FIN-PSH_URG Communication.
                self.fpu_com.pack_data_TPC(pkt)  # filling in the instances

            elif F == 0x00:  # Null (no flag) Communication.
                self.null_com.pack_data_TPC(pkt)  # filling in the instances

        elif pkt.haslayer(UDP):  # for UDP packets
            self.udp_com.pack_data_TPC(pkt)  # filling in the instances

        elif pkt.haslayer(ICMP):  # for ICMP packets
            self.icmp_com.pack_data_TPC(pkt)  # filling in the instances

        return self.s_com, self.sa_com, self.a_com, self.r_com, self.fpu_com, self.null_com, self.udp_com, self.icmp_com

    # Function used to check all port scan attack methods described above. (TCP sS, sX, SN and UDP sU)
    def port_scan_detection(self, pkt, s_com, sa_com, a_com, r_com, fpu_com, null_com, udp_com, icmp_com, time):

        self.port_check(s_com.des_port, sa_com.des_port, [], time, '[TCP -sS]')

        self.port_check(fpu_com.des_port, r_com.des_port, icmp_com.icmp_code, time, '[TCP -sX]')

        self.port_check(null_com.des_port, r_com.des_port, icmp_com.icmp_code, time, '[TCP -sN]')

        self.port_check(udp_com.des_port, r_com.des_port, icmp_com.icmp_code, time, '[UDP -sU]')

    # Checks if conditions are violated to determine if is port scanning attacks.
    def port_check(self, sentP, recive1P, recive2P, time, TypeScan):

        if len(sentP) != 0:
            self.common_port = max(set(sentP), key=sentP.count)  # Determining the most common port

            # Checking that there is no more than 20% of the total communication sent received by the same port
            if 0.2 > (sentP.count(self.common_port) / len(sentP)):
                # Checking if the total amount of responses to the initial packet are over 70% of the communication
                if (len(recive1P) + len(recive2P) / len(sentP)) > 0.7:

                    print(str("[") + str(time) + str("]") + "\t" + "Limit Exceeded, {} Scanning detected".format(
                        TypeScan))
                    logging.critical(
                        str("[") + str(time) + str("]") + "\t" + "Limit Exceeded, {} Port Scanning detected".format(
                            TypeScan))

                else:
                    logging.warning("Potential Port Scanning detected")
            else:
                print(str("[") + str(time) + str("]") + "\t" + "No Port scanning for {}".format(TypeScan))

        else:
            print(str("[") + str(time) + str("]") + "\t" + "No Port scanning for {}".format(TypeScan))

    # Function to determine if there is SYN flooding using checks.
    def syn_detection(self, s_com, sa_com, a_com, time):
        if len(s_com.seq_num) != 0 and len(sa_com.seq_num) != 0:

            self.New = [x + 1 for x in s_com.seq_num]  # adding 1 to every SYN sequence number
            self.New2 = [x + 1 for x in sa_com.seq_num]  # adding 1 to every ACK-SYN sequence number

            self.check1 = set(self.New).issubset(sa_com.ack_num)  # is s_com +1 in sa_com
            self.check2 = set(self.New2).issubset(a_com.ack_num)  # is sa_com +1 in a_com

            self.common_port = max(set(s_com.des_port), key=s_com.des_port.count)  # finding the most common port

            print(self.common_port)

            # if a great proportion (30%) of the syn packets are heading for the same port e.g 80.
            if 0.3 < (s_com.des_port.count(self.common_port) / len(s_com.des_port)):
                self.check3 = True  # indicating potential port scanning
            else:
                self.check3 = False  # indicating SYN flooding is likely aimed at a specific port

            if self.check1:  # Check that there is no communication issues
                # print(str("[")+str(time) + str("]") + "\t"+ "Check 1 complete: communication successful")
                if self.check2:  # If all ACK_SYN are responded with ACK
                    print(str("[") + str(time) + str("]") + "\t" + "No SYN Flooding")
                else:
                    if self.check3:  # Aimed SYN attack at specific port
                        if len(s_com.seq_num) > len(a_com.seq_num) + self.limit:
                            logging.critical(str("[") + str(time) + str("]") + "\t" \
                                             + "Limit Exceeded, SYN Flooding detected")
                            print(str("[") + str(time) + str("]") + "\t" + "Limit Exceeded, SYN Flooding detected")
                        else:
                            logging.warning(str("[") + str(time) + str("]") + "\t" + "SYN overflow SYN > ACK")
                            print(str("[") + str(time) + str("]") + "\t" + "Potential SYN overflow SYN > ACK")
            else:
                logging.warning(str("[") + str(time) + str("]") + "\t" + "Communication Issues: SYN Not RECV")
                print(str("[") + str(time) + str("]") + "\t" + "Communication Issues: SYN Not RECV")


# Class allowing the parsing of individual arrays for each object.
# Separation based on layer and flag
class Sorting_Packets:

    def __init__(self):
        self.seq_num = []  # initialisation of all variables to be appended
        self.ack_num = []
        self.flag = []
        self.src_port = []
        self.des_port = []
        self.icmp_type = []
        self.icmp_code = []

    def pack_data_TPC(self, pkt):
        # Appending the arrays for each object depending on layer
        if pkt.haslayer(TCP):
            self.seq_num.append(pkt[TCP].seq)
            self.ack_num.append(pkt[TCP].ack)
            self.flag.append(pkt[TCP].flags)
            self.src_port.append(pkt[TCP].sport)
            self.des_port.append(pkt[TCP].dport)
            self.icmp_type.append([])
            self.icmp_code.append([])

        elif pkt.haslayer(UDP):
            self.seq_num.append([])
            self.ack_num.append([])
            self.flag.append([])
            self.src_port.append(pkt[UDP].sport)
            self.des_port.append(pkt[UDP].dport)
            self.icmp_type.append([])
            self.icmp_code.append([])


        elif pkt.haslayer(ICMP):
            self.seq_num.append([])
            self.ack_num.append([])
            self.flag.append([])
            self.src_port.append(pkt[ICMP].sport)
            self.des_port.append(pkt[ICMP].dport)
            if pkt.getlayer(ICMP).type == 3 and (int(pkt[ICMP].code) in [1, 2, 3, 9, 10, 13]):
                self.icmp_type.append(pkt[ICMP].type)
                self.icmp_code.append(pkt[ICMP].code)
            else:
                self.icmp_type.append([])
                self.icmp_code.append([])

        return self.seq_num, self.ack_num, self.flag, self.src_port, self.des_port, self.icmp_type, self.icmp_code


def print_log(pkt, time):  # logging all TCP, UDP and ICMP communication
    if pkt.haslayer(TCP):
        logging.info(str("[") + str(time) + str("]") + "\t" + "TCP:{}".format(len(pkt[TCP])) + " Bytes" + \
                     "\t" + "SRC-PORT:" + str(pkt.sport) + " " + "DST-PORT:" + str(pkt.dport) + \
                     "\t" + "IP-Version:" + str(pkt[IP].version) + " " + "SRC-IP:" + str(pkt[IP].src) + \
                     " " + "DST-IP:" + str(pkt[IP].dst) + \
                     "\t" + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:" + str(pkt.dst))

    elif pkt.haslayer(UDP):
        logging.info(str("[") + str(time) + str("]") + "\t" + "UDP:{}".format(len(pkt[UDP])) + " Bytes" + \
                     "\t" + "SRC-PORT:" + str(pkt.sport) + " " + "DST-PORT:" + str(pkt.dport) + \
                     "\t" + "IP-Version:" + str(pkt[IP].version) + " " + "SRC-IP:" + str(pkt[IP].src) + \
                     " " + "DST-IP:" + str(
            pkt[IP].dst) + \
                     "\t" + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:" + str(pkt.dst))

    if pkt.haslayer(ICMP):
        logging.info(str("[") + str(time) + str("]") + "\t" + "ICMP:{}".format(len(pkt[ICMP])) + " Bytes" + \
                     "\t" + "IP-Version:" + str(pkt[IP].version) + " " + "SRC-IP:" + str(
            pkt[IP].src) + " " + "DST-IP:" + str(pkt[IP].dst) + \
                     "\t" + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:" + str(pkt.dst))


def main():
    # Initialising Log file
    logging.basicConfig(filename='sniff1.log', level=logging.INFO, filemode='w', format='%(levelname)s - %(message)s')

    Iden = Identification()
    Iden.start()  # initialising the identification class and start sniffing packets.

    try:
        while True:
            sleep(100)
    except KeyboardInterrupt:  # Control+C to stop running
        print("Stop sniffing")
        Iden.join()  # To stop sniffing


if __name__ == "__main__":  # initialising
    main()