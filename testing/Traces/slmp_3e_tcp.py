#!/usr/bin/env python3
"""Generate slmp_3e_tcp.pcap: binary 3E frames over one TCP connection.

Synthetic traffic, written by this script (no real device involved).
Covers Read Type Name, batch read/write in Q/L and iQ-R subcommand formats,
random read/write, two requests in one TCP segment (remote STOP, then a
remote RUN that fails with an error end code) and a request and response
each split across two TCP segments.
"""

import os
import struct

from slmp_pcaplib import D, M, W, X, Y, Pcap, TcpSession, dev_long, dev_short, request, response

p = Pcap()
s = TcpSession(p, "192.168.10.10", 49152, "192.168.10.20", 5000)
s.open()

# Read Type Name (0101): model name is 16 bytes, space padded, then model code.
s.send(True, request("3E", 0x0101, 0x0000))
s.send(False, response("3E", data=b"R04CPU".ljust(16, b" ") + struct.pack("<H", 0x4800)))

# Device Read (0401/0000): D100, 3 words.
s.send(True, request("3E", 0x0401, 0x0000, dev_short(100, D) + struct.pack("<H", 3)))
s.send(False, response("3E", data=struct.pack("<HHH", 1, 2, 3)))

# Device Write (1401/0001): M10, 4 bits (two bits per byte).
s.send(True, request("3E", 0x1401, 0x0001, dev_short(10, M) + struct.pack("<H", 4) + b"\x11\x00"))
s.send(False, response("3E"))

# Device Read Random (0403/0000): 1 word point (D200), 1 double-word point (D1500).
s.send(True, request("3E", 0x0403, 0x0000, b"\x01\x01" + dev_short(200, D) + dev_short(1500, D)))
s.send(False, response("3E", data=struct.pack("<HI", 0x1234, 0x4C544F4E)))

# Device Write Random (1402/0001): M50 off, Y2F on.
s.send(True, request("3E", 0x1402, 0x0001, b"\x02" + dev_short(50, M) + b"\x00" + dev_short(0x2F, Y) + b"\x01"))
s.send(False, response("3E"))

# Device Read (0401/0002, iQ-R format): W100 (hex), 2 words.
s.send(True, request("3E", 0x0401, 0x0002, dev_long(0x100, W) + struct.pack("<H", 2)))
s.send(False, response("3E", data=struct.pack("<HH", 0xAAAA, 0x5555)))

# Two requests in one segment: Remote Stop (1002), Remote Run (1001, mode 0001, clear mode 02).
both = request("3E", 0x1002, 0x0000, struct.pack("<H", 1)) + \
    request("3E", 0x1001, 0x0000, struct.pack("<HBB", 1, 2, 0))
s.send(True, both)
s.send(False, response("3E"))
s.send(False, response("3E", end_code=0xC059, command=0x1001, subcommand=0x0000))

# A request and its response each split across two segments: X20, 1 word.
req = request("3E", 0x0401, 0x0000, dev_short(0x20, X) + struct.pack("<H", 1))
s.send(True, req[:7])
s.send(True, req[7:])
res = response("3E", data=struct.pack("<H", 0x00FF))
s.send(False, res[:5])
s.send(False, res[5:])

s.close()
p.write(os.path.join(os.path.dirname(os.path.abspath(__file__)), "slmp_3e_tcp.pcap"))
