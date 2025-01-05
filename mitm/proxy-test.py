from netfilterqueue import NetfilterQueue
from scapy.all import IP


def proxy_callback(packet):
    pkt = IP(packet.get_payload())
    pkt.show()
    packet.accept()


try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, proxy_callback)
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
