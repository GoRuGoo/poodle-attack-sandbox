from scapy.all import TCP
from scapy.layers.inet import TCP


def is_sslv3_packet(pkt):
    """
    pkt: scapy.layers.inet.IP
    """

    # TCPがなければそもそも判定できないのでFalse
    if TCP not in pkt:
        return False

    payload = bytes(pkt[TCP].payload)
    version = payload[1:3]

    if version != b'\x03\x00':
        return False

    return True
