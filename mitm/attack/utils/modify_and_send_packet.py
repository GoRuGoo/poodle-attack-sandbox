from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from scapy.all import *
from scapy.layers.inet import IP, TCP

def modify_packet_and_accept(packet, modify_payload):
    del modify_payload[IP].chksum
    del modify_payload[TCP].chksum
    packet.set_payload(bytes(modify_payload))
    packet.accept()