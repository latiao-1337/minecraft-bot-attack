import json
import random
import socket
import string
import struct
import sys
import threading
import time
import uuid
import zlib

try:
    import socks  # PySocks, 代理模式需要: pip install pysocks
except ImportError:
    socks = None

PROTOCOL = 776  # 协议号, 默认 26.2; 运行时可由用户输入覆盖


def version_flags(protocol):
    """按协议号划分时代, 各时代登录流程/包格式不同; 不支持返回 None"""
    if 47 <= protocol <= 735:
        return "legacy"   # 1.8–1.15: 登录开始仅名字(back.py 式), 成功回字符串 UUID
    if 736 <= protocol <= 763:
        return "mid"      # 1.16–1.20.4: 成功回二进制 UUID(1.19+ 带属性数组)
    if protocol >= 764:
        return "modern"   # 1.20.5+(含 26.2): 登录后有配置阶段
    return None           # 1.7 及更老暂不支持


_print_lock = threading.Lock()


def log(tag, msg):
    """线程安全的日志输出(Windows 控制台乱码兜底)"""
    with _print_lock:
        try:
            print("[%s] %s" % (tag, msg))
        except UnicodeEncodeError:
            print("[%s] %s" % (tag, msg.encode("utf-8", "replace").decode("ascii", "replace")))


def random_username():
    chars = string.ascii_letters + string.digits
    return "".join(random.choices(chars, k=random.randint(4, 8)))


# ==================== 基础类型 ====================

def write_varint(n):
    """VarInt 编码"""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def varint_at(data, pos):
    """从 data[pos:] 解码一个 VarInt, 返回 (值, 新位置)"""
    n = 0
    for i in range(5):
        b = data[pos + i]
        n |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return n, pos + i + 1
    raise ValueError("VarInt 过长")


def w_string(s):
    """字符串编码: VarInt 长度 + UTF-8 字节"""
    b = s.encode("utf-8")
    return write_varint(len(b)) + b


def parse_proxy(proxy):
    """解析代理串: ip:port 或 ip:port:user:pass"""
    parts = proxy.split(":")
    if len(parts) == 2:
        return parts[0], int(parts[1]), None, None
    if len(parts) == 4:
        return parts[0], int(parts[1]), parts[2], parts[3]
    raise ValueError("代理格式应为 ip:port 或 ip:port:user:pass: " + proxy)


# ==================== 连接与分包(支持压缩) ====================

class Connection:
    def __init__(self, host, port, proxy=None):
        if proxy:
            if socks is None:
                raise RuntimeError("未安装 PySocks, 请先执行: pip install pysocks")
            ip, p, user, passw = parse_proxy(proxy)
            self.sock = socks.socksocket()
            if user:
                self.sock.set_proxy(socks.SOCKS5, ip, p, username=user, password=passw)
            else:
                self.sock.set_proxy(socks.SOCKS5, ip, p)
            self.sock.settimeout(10)  # 连接代理超时, 防止死代理卡死线程
            self.sock.connect((host, port))
        else:
            self.sock = socket.create_connection((host, port))
        self.threshold = -1  # 压缩阈值, -1 = 未启用
        self.lock = threading.Lock()

    def _read(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("连接被服务器关闭")
            data += chunk
        return data

    def read_varint(self):
        n = 0
        for i in range(5):
            b = self._read(1)[0]
            n |= (b & 0x7F) << (7 * i)
            if not b & 0x80:
                return n
        raise ValueError("VarInt 过长")

    def send(self, pid, payload=b""):
        """发包: 包ID + 载荷, 自动处理压缩与长度前缀"""
        data = bytes([pid]) + payload
        if self.threshold >= 0:
            data = (write_varint(len(data)) + zlib.compress(data)
                    if len(data) >= self.threshold else write_varint(0) + data)
        with self.lock:
            self.sock.sendall(write_varint(len(data)) + data)

    def recv(self):
        """收包, 返回 (包ID, 载荷)"""
        data = self._read(self.read_varint())
        if self.threshold >= 0:
            usize, pos = varint_at(data, 0)
            data = zlib.decompress(data[pos:]) if usize else data[pos:]
        return data[0], data[1:]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ==================== 最小 NBT 解析器(网络版, 用于聊天文本组件) ====================

class NBT:
    """只读解析, 仅支持聊天组件用到的标签"""

    def __init__(self, data):
        self.d, self.p = data, 0

    def _num(self, fmt):
        size = struct.calcsize(fmt)
        v = struct.unpack(">" + fmt, self.d[self.p:self.p + size])[0]
        self.p += size
        return v

    def _str(self):
        n, self.p = varint_at(self.d, self.p)  # 网络 NBT 字符串长度是 VarInt
        s = self.d[self.p:self.p + n].decode("utf-8", "replace")
        self.p += n
        return s

    def _payload(self, t):
        if t == 1:
            return self._num("b")
        if t == 2:
            return self._num("h")
        if t == 3:
            return self._num("i")
        if t == 4:
            return self._num("q")
        if t == 5:
            return self._num("f")
        if t == 6:
            return self._num("d")
        if t == 7:
            n = self._num("i")
            v = self.d[self.p:self.p + n]
            self.p += n
            return v
        if t == 8:
            return self._str()
        if t == 9:  # list
            et = self._num("b")
            return [self._payload(et) for _ in range(self._num("i"))]
        if t == 10:  # compound
            out = {}
            while self.d[self.p] != 0:
                out[self._str()] = self._payload(self._num("b"))
            self.p += 1
            return out
        if t == 11:
            return [self._num("i") for _ in range(self._num("i"))]
        if t == 12:
            return [self._num("q") for _ in range(self._num("i"))]
        raise ValueError("不支持的 NBT 类型 %d" % t)

    def read(self):
        t = self._num("b")
        if t == 0:
            return None
        self._str()  # 顶层名称
        return self._payload(t)


def nbt_text(t):
    """把聊天文本组件(NBT 或 JSON 解析出的 dict/list/str)压成一行字符串"""
    if isinstance(t, str):
        return t
    if isinstance(t, (int, float)):
        return str(t)
    if isinstance(t, dict):
        out = ""
        if "text" in t:
            out += nbt_text(t["text"])
        elif isinstance(t.get("translate"), str):
            out += t["translate"]
            if t.get("with"):
                out += " " + " ".join(nbt_text(x) for x in t["with"])
        for x in t.get("extra", []):
            out += nbt_text(x)
        return out
    if isinstance(t, list):
        return "".join(nbt_text(x) for x in t)
    return ""


def parse_text(data):
    """断开原因/聊天文本: 先按 NBT 解析, 失败退化为 JSON"""
    try:
        return nbt_text(NBT(data).read())
    except Exception:
        try:
            return nbt_text(json.loads(data.decode("utf-8", "replace")))
        except Exception:
            return "<无法解析>"


# ==================== 机器人 ====================

class Bot:
    def __init__(self, host, port, name, tag, proxy=None):
        self.host, self.port, self.name = host, port, name[:16]
        self.tag = tag  # 日志前缀
        self.proxy = proxy
        self.uuid = uuid.uuid4()
        self.conn = None
        self.entity_id = None
        self.mode = version_flags(PROTOCOL)  # legacy / mid / modern

    # ---------- 登录阶段 ----------
    def login(self):
        c = self.conn
        c.send(0x00, write_varint(PROTOCOL) + w_string(self.host)
               + struct.pack(">H", self.port) + write_varint(2))  # Handshake, state=2(登录)
        if self.mode == "legacy" or (self.mode == "mid" and PROTOCOL < 761):
            # 1.8–1.19.1: 登录开始只有名字(和 back.py 一致); 1.19.3+ 才带 UUID
            c.send(0x00, w_string(self.name))
        else:
            c.send(0x00, w_string(self.name) + self.uuid.bytes)
        while True:
            pid, data = c.recv()
            if pid == 0x00:  # Disconnect
                raise RuntimeError("登录被拒绝: " + parse_text(data))
            if pid == 0x01:  # Encryption Request
                raise RuntimeError("服务器要求正版加密登录(online-mode 未关闭)")
            if pid == 0x02:  # Login Success
                self._login_success(data)
                if self.mode == "modern":
                    c.send(0x03)  # Login Acknowledged → 进入配置阶段
                # legacy/mid: 没有配置阶段, 直接进入游戏阶段
                return
            if pid == 0x03:  # Set Compression: 之后所有包走压缩格式
                c.threshold = varint_at(data, 0)[0]
            elif pid == 0x04:  # Login Plugin Request → 回复"不支持"
                mid, _ = varint_at(data, 0)
                c.send(0x02, write_varint(mid) + b"\x00")
            elif pid == 0x05:  # Cookie Request → 回空值
                c.send(0x04, data + b"\x00")

    def _login_success(self, data):
        """解析登录成功包(各时代格式不同)并打印"""
        if self.mode == "legacy":
            n, p = varint_at(data, 0)  # 1.8–1.15: UUID 是字符串(back.py 时代)
            uid = data[p:p + n].decode("utf-8", "replace")
            p += n
        else:
            uid = str(uuid.UUID(bytes=data[:16]))  # 1.16+: UUID 是 16 字节
            p = 16
        n, p = varint_at(data, p)
        uname = data[p:p + n].decode("utf-8", "replace")
        p += n
        if PROTOCOL >= 759:  # 1.19+: 名字后还有属性数组, 跳过
            cnt, p = varint_at(data, p)
            for _ in range(cnt):
                for _ in range(2):
                    n, p = varint_at(data, p)
                    p += n
                if data[p]:  # 属性带签名则再跳过一个字符串
                    p += 1
                    n, p = varint_at(data, p)
                    p += n
                else:
                    p += 1
        log(self.tag, "登录成功! 用户名: %s, UUID: %s" % (uname, uid))

    # ---------- 配置阶段(1.20.5 之后新增) ----------
    def config(self):
        c = self.conn
        while True:
            pid, data = c.recv()
            if pid == 0x00:  # Cookie Request
                c.send(0x01, data + b"\x00")
            elif pid == 0x02:  # Disconnect
                raise RuntimeError("配置阶段被断开: " + parse_text(data))
            elif pid == 0x03:  # Finish Configuration → 确认后配置结束, 进入游戏阶段
                c.send(0x03)
                return
            elif pid == 0x04:  # Keep Alive → 原样回
                c.send(0x04, data)
            elif pid == 0x05:  # Ping → Pong
                c.send(0x05, data)
            elif pid == 0x0B:  # Transfer(转发到别的服务器)
                raise RuntimeError("服务器要求转发, 暂不支持")
            elif pid == 0x0E:  # Known Packs 请求 → 声明"一个数据包都不知道"
                c.send(0x07, write_varint(0))
            elif pid == 0x13:  # Code of Conduct → 接受
                c.send(0x09)
            # 其余(Plugin Message/Registry Data/Feature Flags/Tags/Dialog 等)直接忽略

    # ---------- 游戏阶段 ----------
    def play(self):
        c = self.conn
        if self.mode != "modern":
            # 老版本各版本包ID不同, 进游戏后不解析任何包, 等服务器踢出/断线触发重连
            while True:
                c.recv()
        while True:
            pid, data = c.recv()
            if pid == 0x20:  # Disconnect
                raise RuntimeError("被服务器踢出: " + parse_text(data))
            if pid == 0x31:  # Join Game: 进入游戏!
                self.entity_id = struct.unpack(">i", data[:4])[0]  # 实体 ID(i32)
                log(self.tag, "成功进入游戏! 实体ID: %d" % self.entity_id)
                c.send(0x0E, self._client_info())  # 上报客户端设置
                c.send(0x1E, struct.pack(">ddd", 0, 64, 0) + b"\x01")  # 初始位置
            elif pid == 0x48:  # Synchronize Player Position → 确认传送
                tid, _ = varint_at(data, 0)
                c.send(0x00, write_varint(tid))
            # 不回心跳(Keep Alive/Ping), 等服务器超时踢出后由外层循环重连
            # 其余包(地图/实体/聊天等)不需要解析, 直接忽略

    def _client_info(self):
        """Client Information: locale/视距/聊天模式/皮肤部件/主手等"""
        return (w_string("en_us") + b"\x08" + write_varint(0) + b"\x01" + b"\x7f"
                + write_varint(1) + b"\x00\x00" + write_varint(0))


# ==================== 单个机器人的线程入口 ====================

def bot_worker(idx, host, port, name, proxy=None):
    """连接 → 进服 → 被踢 → 重连, 循环往复(线程为 daemon, Ctrl+C 时随主程序退出)"""
    tag = "bot%02d" % idx if not proxy else "bot%02d@%s" % (idx, proxy.split(":")[0])
    while True:
        bot = Bot(host, port, name, tag, proxy)
        backoff = 0.5
        try:
            bot.conn = Connection(host, port, proxy)
            bot.conn.sock.settimeout(60)  # 登录/配置阶段 60 秒超时
            bot.login()
            if bot.mode == "modern":
                bot.config()  # 1.20.5+ 才有配置阶段
            bot.conn.sock.settimeout(60)  # 游戏阶段不回心跳; 60 秒无数据视为死连接(死代理), 重连
            bot.play()
        except Exception as e:  # 兜底捕获, 保证线程永不死
            log(tag, "连接结束: %s" % e)
            # 正版服务器/缺依赖重连慢一点, 避免刷屏; 其余情况稍等即重连
            backoff = 5 if "加密登录" in str(e) or "PySocks" in str(e) else 0.5
        finally:
            if bot.conn:
                bot.conn.close()
        time.sleep(backoff)


# ==================== 入口 ====================

def main():
    if sys.stdout:
        try:
            # 防 Windows 控制台乱码; 行缓冲保证重定向到文件/管道时也能即时看到输出
            sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            pass

    addr = sys.argv[1].strip() if len(sys.argv) > 1 else input("服务器地址 [127.0.0.1:25565]: ").strip() or "127.0.0.1:25565"

    global PROTOCOL
    proto = sys.argv[2].strip() if len(sys.argv) > 2 else input("协议版本 [776=26.2 默认, 47=1.8.9]: ").strip() or "776"
    PROTOCOL = int(proto)
    mode = version_flags(PROTOCOL)
    if mode is None:
        print("[系统] 不支持的协议版本 %d, 支持范围: 47–735 / 736–763 / 764+" % PROTOCOL)
        return
    log("系统", "协议 %d → %s" % (PROTOCOL, {
        "legacy": "1.8–1.15 老版本流程(back.py 式)",
        "mid": "1.16–1.20.4 流程",
        "modern": "1.20.5+ 配置阶段流程",
    }[mode]))

    host, _, port = addr.rpartition(":")
    if host and port.isdigit():
        port = int(port)
    else:
        host, port = addr, 25565

    # 加载代理列表: socks5.txt 每行一个代理; 玩家数量 = 代理数量(和 back.py 一致)
    proxies = []
    try:
        with open("socks5.txt", encoding="utf-8") as f:
            proxies = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        pass

    if proxies:
        if socks is None:
            print("[系统] 检测到 socks5.txt, 但未安装 PySocks。请先执行: pip install pysocks")
            return
        log("系统", "读取到 %d 个代理, 按代理数量开 %d 个机器人" % (len(proxies), len(proxies)))
    else:
        proxies = [None]
        log("系统", "未找到 socks5.txt, 直连开 1 个机器人")

    count = len(proxies)
    log("系统", "启动 %d 个机器人同时进场 %s:%d (协议 %d), 被踢后自动重进 ..."
        % (count, host, port, PROTOCOL))
    for i in range(count):
        proxy = proxies[i] if proxies[i] else None
        threading.Thread(target=bot_worker,
                         args=(i + 1, host, port, random_username(), proxy),
                         daemon=True).start()  # 和 back.py 一样: 所有机器人同时进场

    try:
        while True:  # 机器人线程无限重连, 主线程挂住等 Ctrl+C
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    log("系统", "全部退出")


if __name__ == "__main__":
    main()
