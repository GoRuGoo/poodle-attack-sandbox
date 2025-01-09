from scapy.all import *

def extract_ssl_message_type(payload):
    """SSL/TLSメッセージタイプを識別する関数"""
    if len(payload) < 5:
        return "Unknown"

    # SSL/TLSメッセージタイプを判定（最初の1バイトがメッセージタイプ）
    msg_type = payload[0]
    if msg_type == 0x16:  # Handshake
        handshake_type = payload[5]
        if handshake_type == 0x01:
            return "Client Hello"
        elif handshake_type == 0x02:
            return "Server Hello"
        elif handshake_type == 0x0E:
            return "Certificate"
        elif handshake_type == 0x0F:
            return "Server Key Exchange"
        elif handshake_type == 0x10:
            return "Certificate Request"
        elif handshake_type == 0x14:
            return "Finished"
        else:
            return "Unknown Handshake"
    elif msg_type == 0x15:  # Alert
        return "Alert"
    elif msg_type == 0x14:  # Application Data
        return "Application Data"
    else:
        return "Unknown"
