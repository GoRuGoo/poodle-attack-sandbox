from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from scapy.layers.inet import IP, TCP
from utils.is_sslv3_packet import is_sslv3_packet
import json

def modify_packet_and_accept(packet, modify_payload):
    del modify_payload[IP].chksum
    del modify_payload[TCP].chksum
    packet.set_payload(bytes(modify_payload))
    packet.accept()

def get_field(layer, field_name):
    return layer.get_field(field_name).i2repr(layer, getattr(layer, field_name))

config = json.load(open('config.json'))


def attack_callback(packet):
    pkt = IP(packet.get_payload())

    print(is_sslv3_packet(pkt))

    packet.accept()

try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, attack_callback)
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
