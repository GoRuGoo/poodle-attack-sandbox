from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from scapy.all import *
from scapy.layers.inet import IP, TCP

def set_modified_payload_to_packet(packet, modify_payload):
    del modify_payload[IP].chksum
    del modify_payload[TCP].chksum
    modify_payload[IP].len = len(modify_payload)
    packet.set_payload(bytes(modify_payload))