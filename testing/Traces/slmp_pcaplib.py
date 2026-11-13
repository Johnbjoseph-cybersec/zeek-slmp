"""Minimal helpers to write synthetic SLMP test captures.

Shared by the generator scripts in this directory. Standard library only.
Every packet is synthetic: no capture from a real device is used. Frame
layouts follow the SLMP Reference Manual SH(NA)-080956ENG-N, binary code.
"""

import struct

LINKTYPE_ETHERNET = 1


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, s, d)
    hdr = hdr[:10] + struct.pack("!H", _checksum(hdr)) + hdr[12:]
    return hdr + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    return s + d + struct.pack("!BBH", 0, proto, length)


def _eth(payload: bytes, to_server: bool) -> bytes:
    client = bytes.fromhex("020000000001")
    server = bytes.fromhex("020000000002")
    dst, src = (server, client) if to_server else (client, server)
    return dst + src + b"\x08\x00" + payload


class Pcap:
    """Collects packets and writes a classic little-endian pcap file."""

    def __init__(self, start: float = 1700000000.0):
        self.t = start
        self.packets = []
        self.ident = 1

    def add(self, frame: bytes, step: float = 0.001):
        self.t += step
        self.packets.append((self.t, frame))

    def write(self, path: str):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
            for ts, frame in self.packets:
                sec = int(ts)
                usec = int(round((ts - sec) * 1_000_000))
                f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
                f.write(frame)

    def next_ident(self) -> int:
        self.ident += 1
        return self.ident


class TcpSession:
    """A TCP connection with handshake, data in either direction and close."""

    def __init__(self, pcap: Pcap, cli: str, cport: int, srv: str, sport: int):
        self.p = pcap
        self.cli, self.cport, self.srv, self.sport = cli, cport, srv, sport
        self.cseq = 1000
        self.sseq = 5000

    def _seg(self, to_server: bool, flags: int, payload: bytes = b"", step: float = 0.001):
        if to_server:
            src, sp, dst, dp, seq, ack = self.cli, self.cport, self.srv, self.sport, self.cseq, self.sseq
        else:
            src, sp, dst, dp, seq, ack = self.srv, self.sport, self.cli, self.cport, self.sseq, self.cseq
        tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
        csum = _checksum(_pseudo(src, dst, 6, len(tcp)) + tcp)
        tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
        self.p.add(_eth(_ip(src, dst, 6, tcp, self.p.next_ident()), to_server), step)
        adv = len(payload) + (1 if flags & 0x03 else 0)
        if to_server:
            self.cseq += adv
        else:
            self.sseq += adv

    def open(self):
        self._seg(True, 0x02)
        self._seg(False, 0x12)
        self._seg(True, 0x10)

    def send(self, to_server: bool, payload: bytes, step: float = 0.001):
        self._seg(to_server, 0x18, payload, step)
        self._seg(not to_server, 0x10)

    def close(self):
        self._seg(True, 0x11)
        self._seg(False, 0x11)
        self._seg(True, 0x10)


def udp(pcap: Pcap, src: str, sport: int, dst: str, dport: int, payload: bytes, to_server: bool = True,
        step: float = 0.001):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = _checksum(_pseudo(src, dst, 17, len(seg)) + seg) or 0xFFFF
    seg = seg[:6] + struct.pack("!H", csum) + seg[8:]
    pcap.add(_eth(_ip(src, dst, 17, seg, pcap.next_ident()), to_server), step)


# ---------------------------------------------------------------------------
# SLMP binary frame builders


def route(network=0x00, station=0xFF, module_io=0x03FF, multidrop=0x00) -> bytes:
    return struct.pack("<BBHB", network, station, module_io, multidrop)


def _subheader(kind: str, request: bool, serial: int) -> bytes:
    if kind == "3E":
        return b"\x50\x00" if request else b"\xD0\x00"
    first = {"4E": (0x54, 0xD4), "EXT": (0x68, 0xE8)}[kind][0 if request else 1]
    return bytes([first, 0]) + struct.pack("<HH", serial, 0)


def request(kind: str, command: int, subcommand: int, data: bytes = b"", serial: int = 0,
            timer: int = 0x0010, ext_station: int = 0, **rt) -> bytes:
    body = struct.pack("<HHH", timer, command, subcommand)
    if kind == "EXT":
        body += b"\x00" * 6
    body += data
    head = _subheader(kind, True, serial) + route(**rt)
    if kind == "EXT":
        head += struct.pack("<BH", 0, ext_station)
    return head + struct.pack("<H", len(body)) + body


def response(kind: str, end_code: int = 0, data: bytes = b"", serial: int = 0, command: int = 0,
             subcommand: int = 0, ext_station: int = 0, error_route: bytes = None, **rt) -> bytes:
    body = struct.pack("<H", end_code)
    if kind == "EXT":
        body += struct.pack("<HH", command, subcommand) + b"\x00" * 6
    if end_code != 0:
        body += error_route if error_route is not None else route(**rt)
        if kind != "EXT":
            body += struct.pack("<HH", command, subcommand)
    body += data
    head = _subheader(kind, False, serial) + route(**rt)
    if kind == "EXT":
        head += struct.pack("<BH", 0, ext_station)
    return head + struct.pack("<H", len(body)) + body


def dev_short(number: int, code: int) -> bytes:
    """Device for subcommand 0000/0001: 3-byte number, 1-byte code."""
    return number.to_bytes(3, "little") + bytes([code & 0xFF])


def dev_long(number: int, code: int) -> bytes:
    """Device for subcommand 0002/0003: 4-byte number, 2-byte code."""
    return struct.pack("<IH", number, code)


# Binary device codes (SH(NA)-080956ENG-N, section 5.2).
D, W, M, X, Y, TN = 0xA8, 0xB4, 0x90, 0x9C, 0x9D, 0xC2
