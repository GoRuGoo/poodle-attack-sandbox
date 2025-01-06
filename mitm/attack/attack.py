from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from scapy.all import *
from scapy.layers.inet import IP, TCP
from utils.is_sslv3_packet import is_sslv3_packet
import json

load_layer('tls')


config = json.load(open('config.json'))

def get_field(layer,field_name):
    return layer.get_field(field_name).i2repr(layer, getattr(layer, field_name))

def attack_callback(packet):
    pkt = IP(packet.get_payload())

    packet.accept()

try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, attack_callback)
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
