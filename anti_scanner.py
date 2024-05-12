from scapy.all import *


def send_ack(recv_pkt):
    IP_src=recv_pkt[IP].src
    IP_dst=recv_pkt[IP].dst
    TCP_sport=recv_pkt[TCP].sport
    TCP_dport = recv_pkt[TCP].dport
    TCP_seq = recv_pkt[TCP].seq
    TCP_ack = recv_pkt[TCP].ack
    send_pkt=IP(src=IP_dst,dst=IP_src)/TCP(dport=TCP_sport, sport=TCP_dport, ack=TCP_seq+1, seq=12345678, flgas="SAE")
    send(send_pkt)

sniff(filter="tcp[tcpflags] & (tcp-syn)!=0 and tcp[tcpflags]& (tcp-ack)==0", prn=send_ack, iface="ens33")
