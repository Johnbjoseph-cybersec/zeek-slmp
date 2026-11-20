#!/usr/bin/env python3
"""Build PCAPs from the Apache PLC4X SLMP reference vectors.

The frame bytes are copied verbatim from
protocols/slmp/src/test/resources/protocols/slmp/ParserSerializerTestsuite.xml
in apache/plc4x (develop), which derives them from the worked examples in
Mitsubishi's MELSEC Communication Protocol Reference Manual (SH-080008).
Nothing here is shared with the zeek-slmp test helpers: the pcap, Ethernet,
IPv4, TCP and UDP encoding is written from scratch with the standard library.

PLC4X has no response vector for the multi-block read (0x0406), so that
request goes out last with no reply and should be logged as no_response.

Output:
  slmp-plc4x-vectors-tcp.pcap  one TCP connection, client 50000 -> server 5010
  slmp-plc4x-vectors-udp.pcap  one UDP flow,       client 50001 -> server 5010
"""

import os
import struct

# (direction, hex) in wire order; "c" = client to server, "s" = server to client
FRAMES = [
    ("c", "500000ffff03000c000000010400005e0100a80200"),  # 3E Batch Read req, D350 x2
    ("s", "d00000ffff030006000000ab560f17"),  # 3E Batch Read resp
    ("c", "500000ffff030024000000030400000403000000a8000000c2640000902000009cdc0500a86001009d57040090"),  # Random Read req
    ("s", "d00000ffff03001600000095190212302049484e4f544cafb9dec3b7bcddba"),  # Random Read resp
    ("c", "500000ffff030026000000060400000203000000a80400000100b40800000000900200800000900200000100a00300"),  # Multi-block req
]

CLIENT_MAC = bytes.fromhex("020000000a0a")
SERVER_MAC = bytes.fromhex("020000001414")
CLIENT_IP = bytes([192, 168, 77, 10])
SERVER_IP = bytes([192, 168, 77, 20])
SERVER_PORT = 5010
START_TS = 1763640000.0  # fixed so output is reproducible


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


class Pcap:
    def __init__(self):
        self.records = []

    def add(self, ts: float, frame: bytes):
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        self.records.append(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)

    def write(self, path: str):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # LINKTYPE_ETHERNET
            for r in self.records:
                f.write(r)


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes, ident: int) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def ether(src: bytes, dst: bytes, payload: bytes) -> bytes:
    return dst + src + b"\x08\x00" + payload


def tcp_seg(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    c = csum(pseudo + hdr + payload)
    return hdr[:16] + struct.pack("!H", c) + hdr[18:] + payload


def udp_dgram(src_ip, dst_ip, sport, dport, payload):
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 17, length)
    c = csum(pseudo + hdr + payload) or 0xFFFF
    return hdr[:6] + struct.pack("!H", c) + payload


SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def build_tcp(path: str):
    p = Pcap()
    ts = START_TS
    ident = 1
    cport = 50000
    cseq, sseq = 1000, 5000

    def emit(to_server: bool, flags: int, payload: bytes = b""):
        nonlocal ts, ident, cseq, sseq
        if to_server:
            seg = tcp_seg(CLIENT_IP, SERVER_IP, cport, SERVER_PORT, cseq, sseq, flags, payload)
            pkt = ether(CLIENT_MAC, SERVER_MAC, ipv4(CLIENT_IP, SERVER_IP, 6, seg, ident))
            cseq += len(payload) + (1 if flags & (SYN | FIN) else 0)
        else:
            seg = tcp_seg(SERVER_IP, CLIENT_IP, SERVER_PORT, cport, sseq, cseq, flags, payload)
            pkt = ether(SERVER_MAC, CLIENT_MAC, ipv4(SERVER_IP, CLIENT_IP, 6, seg, ident))
            sseq += len(payload) + (1 if flags & (SYN | FIN) else 0)
        p.add(ts, pkt)
        ident += 1

    # handshake (SYN carries no ACK)
    seg = tcp_seg(CLIENT_IP, SERVER_IP, cport, SERVER_PORT, cseq, 0, SYN)
    p.add(ts, ether(CLIENT_MAC, SERVER_MAC, ipv4(CLIENT_IP, SERVER_IP, 6, seg, ident)))
    ident += 1
    cseq += 1
    ts += 0.0005
    emit(False, SYN | ACK)
    ts += 0.0005
    emit(True, ACK)

    for direction, hexstr in FRAMES:
        ts += 0.010 if direction == "c" else 0.002
        emit(direction == "c", PSH | ACK, bytes.fromhex(hexstr))
        ts += 0.0002
        emit(direction != "c", ACK)

    ts += 0.100
    emit(True, FIN | ACK)
    ts += 0.0005
    emit(False, FIN | ACK)
    ts += 0.0005
    emit(True, ACK)
    p.write(path)


def build_udp(path: str):
    p = Pcap()
    ts = START_TS + 10
    ident = 1
    cport = 50001
    for direction, hexstr in FRAMES:
        ts += 0.010 if direction == "c" else 0.002
        payload = bytes.fromhex(hexstr)
        if direction == "c":
            d = udp_dgram(CLIENT_IP, SERVER_IP, cport, SERVER_PORT, payload)
            pkt = ether(CLIENT_MAC, SERVER_MAC, ipv4(CLIENT_IP, SERVER_IP, 17, d, ident))
        else:
            d = udp_dgram(SERVER_IP, CLIENT_IP, SERVER_PORT, cport, payload)
            pkt = ether(SERVER_MAC, CLIENT_MAC, ipv4(SERVER_IP, CLIENT_IP, 17, d, ident))
        p.add(ts, pkt)
        ident += 1
    p.write(path)


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    build_tcp(os.path.join(here, "slmp-plc4x-vectors-tcp.pcap"))
    build_udp(os.path.join(here, "slmp-plc4x-vectors-udp.pcap"))
