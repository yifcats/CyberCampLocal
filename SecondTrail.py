#! /usr/bin/python
import os
from scapy.all import *
from scapy.layers.inet import TCP
import datetime
import logging



# Which interface to look at is interactive.
def which_interface():
    while True:
        print("Enter a valid Interface: " + str(get_if_list()))
        intface=input("Enter the interface: ")

        if intface in list(get_if_list()[:]):
            break
    return intface


def sniffing_tool():
    intface=which_interface()
    return sniff(iface=intface,prn=packet_handler)





limit=10

def packet_handler(pkt):
    time=datetime.datetime.now()
    print_log(pkt,time)


    s_com1,sa_com1,a_com1,r_com1,fpu_COM1,null_com1,udp_com1,icmp_com1=pack_sorter_TCP(pkt)

    # if pkt.haslayer(TCP):
    #     syn_detection(s_com1,sa_com1,a_com1,r_com1,time)

    port_scan_detection(pkt,s_com1,sa_com1,a_com1,r_com1,fpu_COM1,null_com1,udp_com1,icmp_com1,time)


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




def port_scan_detection(pkt,s_com,sa_com,a_com,r_com,fpu_com,null_com,udp_com,icmp_com,time):
    # udp_P = [x for x in range(0, 65535)]
    # tcp_P = [x for x in range(0, 65535)]

    # print(len(r_com.des_port))
    if len(s_com.seq_num) != 0 and len(r_com.des_port):

        New=[x+1 for x in s_com.seq_num]
        check1_sS=set(New).issubset(sa_com.ack_num) # is s_com +1 in sa_com


        common_port=max(set(s_com.des_port), key=s_com.des_port.count)

        # if check1_sS:
            # print(str("[")+str(time) + str("]") + "\t"+ "Check 1 complete: communication secsessful")
        if 0.01 > (s_com.des_port.count(common_port)/ len(s_com.des_port)):
            print()
            if (len(r_com.src_port)/len(s_com.src_port) > 0.7) or check1_sS:
                print(str("[") + str(time) + str("]") + "\t" + "Limit Exceeded, Port Scaninig detected")
                logging.warning(str("[") + str(time) + str("]") + "\t" + "Limit Exceeded, Port Scaninig detected")
            else:
                print("Port Scaninig detected potential")
        else:
            print(str("[") + str(time) + str("]") + "\t" + "No Port scanning")

    # if TCP in pkt and pkt[TCP].dport in tcp_P:
    #     return True
    # elif UDP in pkt and pkt[UDP].dport in udp_P:
    #     return True
    # elif ICMP in pkt:
    #     return True
    # else:
    #     return False


def syn_detection(s_com,sa_com,a_com,r_com,time):
    if len(s_com.seq_num) !=0 and len(sa_com.seq_num) !=0:
        # print("seq: " + str(s_com.seq_num) + str(s_com.flag))
        # print("ack: " + str(sa_com.ack_num) + str(sa_com.flag))


        New=[x+1 for x in s_com.seq_num]
        New2=[x+1 for x in sa_com.seq_num]

        check1=set(New).issubset(sa_com.ack_num) # is s_com +1 in sa_com
        check2=set(New2).issubset(a_com.ack_num) # is sa_com +1 in a_com



        # if a great proportion (30%) of the syn packets are heading for the same port 80.
        if 0.3 < (s_com.des_port.count(80)/len(s_com.des_port)):
            check3=True
        else:
            check3=False


        if check1:
            print(str("[")+str(time) + str("]") + "\t"+ "Check 1 complete: communication secsessful")
            if check2:
                print(str("[") + str(time) + str("]") + "\t"+ "Check 2 complete: No SYN Flooding")
            else:
                if check3:
                    if len(s_com.seq_num) > len(a_com.seq_num) + limit:
                        logging.warning(str("[") + str(time) + str("]") + "\t"+ "Check 2 Failed: Limit Exceeded, SYN Flooding detected")
                        print(str("[") + str(time) + str("]") + "\t"+ "Check 2 Failed: Limit Exceeded, SYN Flooding detected")
                    else:
                        logging.warning(str("[") + str(time) + str("]") + "\t"+ "Check 2 Failed: SYN overflow SYN > ACK")
                        print(str("[") + str(time) + str("]") + "\t"+ "Check 2 Failed: SYN overflow SYN > ACK")
        else:
            logging.warning(str("[") + str(time) + str("]")+ "\t"+ "Communication Issues: SYN Not RECV")




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
            self.src_port.append(pkt[UDP].sport)
            self.des_port.append(pkt[UDP].dport)
            self.icmp_type.append(pkt[ICMP].type)
            self.icmp_code.append(pkt[ICMP].code)

        return self.seq_num, self.ack_num, self.flag, self.src_port,self.des_port,self.icmp_type,self.icmp_code

s_com=Sorting_Packets()
sa_com=Sorting_Packets()
a_com=Sorting_Packets()
r_com=Sorting_Packets()
fpu_com=Sorting_Packets()
s_com=Sorting_Packets()
null_com=Sorting_Packets()

udp_com=Sorting_Packets()
icmp_com=Sorting_Packets()


def pack_sorter_TCP(pkt):
    if pkt.haslayer(TCP):
        F=pkt['TCP'].flags
        if F == 0x02 and F != 0x10:
            # print(pkt.summary())

            s_com.pack_data_TPC(pkt)
            # print("seq: " + str(s_com.seq_num) + str(s_com.flag))
            # print("ack: " + str(s_com.ack_num) + str(s_com.flag))

        elif F == 0x12:
            # print(pkt.summary())

            sa_com.pack_data_TPC(pkt)
            # print("seq: " + str(sa_com.seq_num) + str(sa_com.flag))
            # print("ack: " + str(sa_com.ack_num) + str(sa_com.flag))

        elif F == 0x10:
            # print(pkt.summary())

            a_com.pack_data_TPC(pkt)
            # print("seq: " + str(a_com.seq_num) + str(a_com.flag))
            # print("ack: " + str(a_com.ack_num) + str(a_com.flag))
            # print(a_com.seq_num)
        elif F == 0x4: # rst TPC_sS
            # print(pkt.summary())

            r_com.pack_data_TPC(pkt)
            # print(r_com.seq_num)

        elif F == 0x29: # FPU TPC_sX
            # print(pkt.summary())

            fpu_com.pack_data_TPC(pkt)
        elif F == 0x00:
            # print(pkt.summary())
            null_com.pack_data_TPC(pkt)



    elif pkt.haslayer(UDP):
        # print(pkt.summary())

        udp_com.pack_data_TPC(pkt)

    elif pkt.haslayer(ICMP):
        # print(pkt.summary())
        icmp_com.pack_data_TPC(pkt)

    return s_com,sa_com,a_com,r_com,fpu_com,null_com,udp_com,icmp_com


# s_com=[]
# sa_com=[]
# a_com=[]
# r_com=[]
# fpu_COM=[]
# null_com=[]

def main():

    logging.basicConfig(filename='sniff1.log', level=logging.INFO, filemode='w', format='%(levelname)s - %(message)s')
    packet_handler(sniffing_tool())
    return


if __name__== "__main__":  # initilising
    main()