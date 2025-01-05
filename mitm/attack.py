from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from scapy.layers.inet import IP, TCP
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

    # Check if the packet is from the target
    if pkt.src == config['target'] and TCP in pkt:
        # Check if the payload contains a TLS handshake (this is basic, you may need further checks)
        if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:  # Check for HTTPS traffic
            payload = bytes(pkt[TCP].payload)
            if len(payload) > 5:  # Minimal size for a valid TLS handshake (ClientHello)
                # Check for SSL/TLS version (TLS handshake type, version is typically in ClientHello)
                if payload[0] == 22:  # TLS handshake type (ClientHello)
                    version = payload[1:3]
                    # SSLv3 version is 0x0300
                    if version == b'\x03\x00':
                        print("SSLv3 Detected")
                    else:
                        print("Not SSLv3, version:", version)
            else:
                print("Not a valid handshake packet")
    packet.accept()

try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, attack_callback)
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
