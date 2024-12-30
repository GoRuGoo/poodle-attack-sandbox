from netfilterqueue import NetfilterQueue
from scapy.all import IP

pkt = None

def callback(packet):
    global pkt
    pkt = IP(packet.get_payload())
    print(pkt)
    packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, callback)

try:
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
