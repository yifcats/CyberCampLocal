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

seq_num_syn=[]
seq_num_acksyn=[]
seq_num_ack=[]

ack_num_syn=[]
ack_num_acksyn=[]
ack_num_ack=[]

flag_syn=[]
flag_acksyn=[]
flag_ack=[]


limit=10

def packet_handler(pkt):
    time=datetime.datetime.now()
    print_log(pkt,time)

    syn_detection(pkt,time)
    # port_scan_detection(pkt)


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




def port_scan_detection(pkt):
    udp_P = [x for x in range(0, 65535)]
    tcp_P = [x for x in range(0, 65535)]

    if TCP in pkt and pkt[TCP].dport in tcp_P:
        return True
    elif UDP in pkt and pkt[UDP].dport in udp_P:
        return True
    elif ICMP in pkt:
        return True
    else:
        return False


def syn_detection(pkt,time):

    if pkt.haslayer(TCP):

        F=pkt['TCP'].flags
        SYN_COM=syn_find(pkt,F)
        KSYN_COM=ack_syn_find(pkt,F)
        K_COM=ack_find(pkt,F)

        if len(SYN_COM[0]) !=0 and len(KSYN_COM[0]) !=0:

            New=[x+1 for x in SYN_COM[0]]
            New2=[x+1 for x in KSYN_COM[0]]

            check1=set(New).issubset(KSYN_COM[1])
            check2=set(New2).issubset(K_COM[1])

            if check1:
                print(str("[")+str(time) + str("]") + "\t"+ "Check 1 complete: communication secsessful")
                if check2:
                    print(str("[") + str(time) + str("]") + "\t"+ "Check 2 complete: No SYN Flooding")
                else:
                    if len(New) > len(K_COM[1]) + limit:
                        logging.warning(str("[") + str(time) + str("]") + "\t"+ "Limit Exceeded, Check 2 Failed: SYN Flooding detected")
                        print(str("[") + str(time) + str("]") + "\t"+ "Limit Exceeded, Check 2 Failed: SYN Flooding detected")
                    # else:
                        # logging.warning(str("[") + str(time) + str("]") + "\t"+ "Check 2 Failed: SYN overflow SYN > ACK")
            else:
                logging.warning(str("[") + str(time) + str("]")+ "\t"+ "Communication Issues: SYN Not RECV")


def syn_find(pkt,F):
    if F == 0x02 and F != 0x10:
        seq_num_syn.append(pkt[TCP].seq)
        ack_num_syn.append(pkt[TCP].ack)
        flag_syn.append(pkt['TCP'].flags)

    return seq_num_syn, ack_num_syn,flag_syn

def ack_syn_find(pkt,F):
    if F == 0x12:
        seq_num_acksyn.append(pkt[TCP].seq)
        ack_num_acksyn.append(pkt[TCP].ack)
        flag_acksyn.append(pkt['TCP'].flags)

    return seq_num_acksyn, ack_num_acksyn, flag_acksyn

def ack_find(pkt,F):
    if F == 0x10:
        seq_num_ack.append(pkt[TCP].seq)
        ack_num_ack.append(pkt[TCP].ack)
        flag_ack.append(pkt['TCP'].flags)
    return seq_num_ack, ack_num_ack, flag_ack




def main():
    logging.basicConfig(filename='sniff1.log', level=logging.INFO, filemode='w', format='%(levelname)s - %(message)s')
    packet_handler(sniffing_tool())
    return


if __name__== "__main__":  # initilising
    main()