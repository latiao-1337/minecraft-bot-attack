import socket
import threading
import random
import string
import time
import socks


def random_username():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=random.randint(4, 8)))


class MCClient:
    def __init__(self, host, port, proxy=None):
        self.host = host
        self.port = port
        self.proxy = proxy
        self.running = True
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while self.running:
            sock = None
            try:
                if self.proxy:
                    ip, p = self.proxy.split(':')
                    sock = socks.socksocket()
                    sock.set_proxy(socks.SOCKS5, ip, int(p))
                else:
                    sock = socket.socket()

                sock.connect((self.host, self.port))
                sock.setblocking(False)

                self.send_handshake_login(sock)
                self.recv_loop(sock)

            except:
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass

    def recv_loop(self, sock):
        while self.running:
            try:
                if not sock.recv(1024):
                    return
            except BlockingIOError:
                continue
            except:
                return

    def send_handshake_login(self, sock):
        def varint(n):
            b = bytearray()
            while n:
                byte = n & 0x7F
                n >>= 7
                b.append(byte | (0x80 if n else 0))
            if not b:
                b.append(0)
            return bytes(b)

        def string(s):
            data = s.encode()
            return varint(len(data)) + data

        # handshake
        hs = (
            varint(0) +
            varint(version) +
            string(serverip) +
            serverport.to_bytes(2, 'big') +
            varint(2)
        )
        sock.send(varint(len(hs)) + hs)

        # login
        login = varint(0) + string(random_username())
        sock.send(varint(len(login)) + login)


def run_clients(host, port, proxies):
    return [MCClient(host, port, p) for p in proxies]


if __name__ == "__main__":
    serverip = input("server ip: ").strip()
    serverport = int(input("port: "))
    version = int(input("protocol version 1.8.9=47: "))

    try:
        with open("socks5.txt") as f:
            proxies = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        proxies = [None]

    clients = run_clients(serverip, serverport, proxies)



while True:
        time.sleep(60)
