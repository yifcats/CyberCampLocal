#! /usr/bin/python
import os
from scapy.all import *
from scapy.layers.inet import TCP
import datetime
from time import sleep
import logging
from threading import Thread, Event


# Which interface to look at is interactive.
def which_interface():
    while True:
        print("Enter a valid Interface: " + str(get_if_list()))
        intface=input("Enter the interface: ")

        if intface in list(get_if_list()[:]):
            break
    return intface




class Identification(Thread):

    def __init__(self):
        super().__init__()

        self.daemon = True

        self.Interface=which_interface()
        self.stop_sniffer = Event()

        self.s_com = Sorting_Packets()
        self.sa_com = Sorting_Packets()
        self.a_com = Sorting_Packets()
        self.r_com = Sorting_Packets()
        self.fpu_com = Sorting_Packets()
        self.s_com = Sorting_Packets()
        self.null_com = Sorting_Packets()
        self.udp_com = Sorting_Packets()
        self.icmp_com = Sorting_Packets()
        self.limit=5

    def run(self):  # Calling the function when initilising the class.
        sniff(iface=self.Interface, prn=self.packet_handler)

    def join(self, timeout=0):  # creating a stop
        self.stop_sniffer.set()
        super().join(timeout)
        return self.stop_sniffer.isSet()

    def packet_handler(self,pkt):
        time = datetime.datetime.now()
        print_log(pkt, time)

        self.s_com1,self.sa_com1,self.a_com1,self.r_com1,self.fpu_COM1,self.null_com1,self.udp_com1,self.icmp_com1=self.pack_sorter_TCP(pkt)

        if pkt.haslayer(TCP):
            self.syn_detection(self.s_com1,self.sa_com1,self.a_com1,self.r_com1,time)

        self.port_scan_detection(pkt,self.s_com1,self.sa_com1,self.a_com1,self.r_com1,self.fpu_COM1,self.null_com1,self.udp_com1,self.icmp_com1,time)


    def pack_sorter_TCP(self,pkt):
        if pkt.haslayer(TCP):
            F = pkt['TCP'].flags
            if F == 0x02 and F != 0x10:
                self.s_com.pack_data_TPC(pkt)

            elif F == 0x12:
                self.sa_com.pack_data_TPC(pkt)

            elif F == 0x10:
                self.a_com.pack_data_TPC(pkt)

            elif F == 0x14:  # rst-ack TPC_sS
                self.r_com.pack_data_TPC(pkt)

            elif F == 0x29:  # FPU TPC_sX
                self.fpu_com.pack_data_TPC(pkt)

            elif F == 0x00:
                self.null_com.pack_data_TPC(pkt)

        elif pkt.haslayer(UDP):
            self.udp_com.pack_data_TPC(pkt)

        elif pkt.haslayer(ICMP):
            self.icmp_com.pack_data_TPC(pkt)

        return self.s_com, self.sa_com, self.a_com, self.r_com, self.fpu_com, self.null_com, self.udp_com, self.icmp_com


    def port_scan_detection(self,pkt,s_com,sa_com,a_com,r_com,fpu_com,null_com,udp_com,icmp_com,time):

        self.port_check(s_com.des_port,sa_com.des_port,[],r_com.des_port,time,'TCP sS')

        self.port_check(fpu_com.des_port, r_com.des_port, icmp_com.icmp_code, r_com.des_port, time, 'TCP sX')

        self.port_check(null_com.des_port, r_com.des_port, icmp_com.icmp_code, r_com.des_port, time, 'TCP sN')

        self.port_check(udp_com.des_port, r_com.des_port, icmp_com.icmp_code, r_com.des_port, time, 'UDP sU')


    def port_check(self,sentP, recive1P, recive2P, sent2P, time, TypeScan):

        if len(sentP) != 0:
            self.common_port = max(set(sentP), key=sentP.count)

            if 0.2 > (sentP.count(self.common_port) / len(sentP)):
                if (len(recive1P) + len(recive2P) / len(sentP)) > 0.7:

                    print(str("[") + str(time) + str("]") + "\t" + "Limit Exceeded, {} Scaninig detected".format(
                        TypeScan))
                    logging.warning(
                        str("[") + str(time) + str("]") + "\t" + "Limit Exceeded, {} Port Scaninig detected".format(
                            TypeScan))

                else:
                    print("Potential Port Scaninig detected")
            else:
                print(str("[") + str(time) + str("]") + "\t" + "No Port scanning")


    def syn_detection(self,s_com,sa_com,a_com,r_com,time):
        if len(s_com.seq_num) !=0 and len(sa_com.seq_num) !=0:

            self.New=[x+1 for x in s_com.seq_num]
            self.New2=[x+1 for x in sa_com.seq_num]

            self.check1=set(self.New).issubset(sa_com.ack_num) # is s_com +1 in sa_com
            self.check2=set(self.New2).issubset(a_com.ack_num) # is sa_com +1 in a_com

            self.common_port = max(set(s_com.des_port), key=s_com.des_port.count) # finding the most comman port


            # if a great proportion (30%) of the syn packets are heading for the same port e.g 80.
            if 0.3 < (s_com.des_port.count(self.common_port)/len(s_com.des_port)):
                self.check3=True
            else:
                self.check3=False


            if self.check1:
                # print(str("[")+str(time) + str("]") + "\t"+ "Check 1 complete: communication secsessful")
                if self.check2:
                    print(str("[") + str(time) + str("]") + "\t"+ "No SYN Flooding")
                else:
                    if self.check3:
                        if len(s_com.seq_num) > len(a_com.seq_num) + self.limit:
                            logging.warning(str("[") + str(time) + str("]") + "\t"+ "Limit Exceeded, SYN Flooding detected")
                            print(str("[") + str(time) + str("]") + "\t"+ "Limit Exceeded, SYN Flooding detected")
                        else:
                            # logging.warning(str("[") + str(time) + str("]") + "\t"+ "Check 2 Failed: SYN overflow SYN > ACK")
                            print(str("[") + str(time) + str("]") + "\t"+ "Potential SYN overflow SYN > ACK")
            else:
                logging.warning(str("[") + str(time) + str("]")+ "\t"+ "Communication Issues: SYN Not RECV")
                print('com error')



class Sorting_Packets:

    def __init__(self):
        self.seq_num = []
        self.ack_num = []
        self.flag = []
        self.src_port = []
        self.des_port = []
        self.icmp_type= []
        self.icmp_code=[]
    def pack_data_TPC(self,pkt):

        if  pkt.haslayer(TCP):
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

        return self.seq_num, self.ack_num, self.flag, self.src_port,self.des_port,self.icmp_type,self.icmp_code

def print_log(pkt,time):
    if pkt.haslayer(TCP):
        name_pkt=len(pkt[TCP])
        logging.info(str("[") + str(time) + str("]") + "\t" + "TCP:{}".format(name_pkt) + " Bytes" + \
                     "\t" + "SRC-PORT:" + str(pkt.sport) + " " + "DST-PORT:" + str(pkt.dport) + \
                     "\t" + "IP-Version:" + str(pkt[IP].version) + " " + "SRC-IP:" + str(pkt[IP].src) + \
                     " " + "DST-IP:" + str(pkt[IP].dst) + \
                     "\t" + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:" + str(pkt.dst))


    elif pkt.haslayer(UDP):
        name_pkt = len(pkt[UDP])
        logging.info(str("[") + str(time) + str("]") + "\t" + "UDP:{}".format(len(pkt[UDP])) + " Bytes" + \
                     "\t" + "SRC-PORT:" + str(pkt.sport) + " " + "DST-PORT:" + str(pkt.dport) + \
                     "\t" + "IP-Version:" + str(pkt[IP].version) + " " + "SRC-IP:" + str(pkt[IP].src) + \
                     " " + "DST-IP:" + str(
            pkt[IP].dst) + \
                     "\t" + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:" + str(pkt.dst))
    if pkt.haslayer(ICMP):
        name_pkt = len(pkt[ICMP])
        logging.info(str("[") + str(time) + str("]") + "\t" + "ICMP:{}".format(name_pkt) + " Bytes" + \
                     "\t" + "IP-Version:" + str(pkt[IP].version) + " " + "SRC-IP:" + str(
            pkt[IP].src) + " " + "DST-IP:" + str(pkt[IP].dst) + \
                     "\t" + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:" + str(pkt.dst))


def main():
    logging.basicConfig(filename='sniff1.log', level=logging.INFO, filemode='w', format='%(levelname)s - %(message)s')
    Iden=Identification()
    Iden.start()

    try:
        while True:
            sleep(100)
    except KeyboardInterrupt:
        print("Stop sniffing")
        Iden.join()  # to be able to stop sniffing





if __name__== "__main__":  # initilising
    main()