#!/usr/bin/env python3
"""Generate slmp_not_slmp.pcap: port selection by content, not by number.

Synthetic traffic, written by this script (no real device involved).
1. TCP 5000: an HTTP request and response (for example a Flask dev server).
2. UDP 5004: an RTP packet.
3. TCP 6000: a valid 3E pair on a port outside 5000-5009.
4. UDP 6001: a valid 4E pair on a port outside 5000-5009.
"""

import os
import struct

from slmp_pcaplib import D, Pcap, TcpSession, dev_short, request, response, udp

p = Pcap()

s = TcpSession(p, "192.168.30.10", 49400, "192.168.30.20", 5000)
s.open()
s.send(True, b"GET / HTTP/1.1\r\nHost: 192.168.30.20:5000\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\n\r\n")
s.send(False, b"HTTP/1.1 200 OK\r\nServer: Werkzeug/3.0.1 Python/3.12.2\r\nContent-Type: text/html\r\n"
              b"Content-Length: 5\r\nConnection: close\r\n\r\nhello")
s.close()

rtp = struct.pack("!BBHII", 0x80, 0x00, 1, 160, 0x12345678) + b"\xff" * 160
udp(p, "192.168.30.10", 40000, "192.168.30.21", 5004, rtp)
udp(p, "192.168.30.21", 5004, "192.168.30.10", 40000, rtp, to_server=False)

s = TcpSession(p, "192.168.30.10", 49401, "192.168.30.22", 6000)
s.open()
s.send(True, request("3E", 0x0401, 0x0000, dev_short(10, D) + struct.pack("<H", 1)))
s.send(False, response("3E", data=struct.pack("<H", 7)))
s.close()

udp(p, "192.168.30.10", 50100, "192.168.30.23", 6001,
    request("4E", 0x0401, 0x0000, dev_short(11, D) + struct.pack("<H", 1), serial=0x0042))
udp(p, "192.168.30.23", 6001, "192.168.30.10", 50100,
    response("4E", data=struct.pack("<H", 8), serial=0x0042), to_server=False)

p.write(os.path.join(os.path.dirname(os.path.abspath(__file__)), "slmp_not_slmp.pcap"))
