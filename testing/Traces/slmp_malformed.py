#!/usr/bin/env python3
"""Generate slmp_malformed.pcap: malformed SLMP frames.

Synthetic traffic, written by this script (no real device involved).
1. TCP 5002: a valid 3E request/response pair, then a frame with an unknown
   subheader (99H 00H).
2. UDP 5003: a 4E request whose fixed bytes after the serial number are not 0.
3. UDP 5004: a 3E request whose request data length is larger than the datagram.
"""

import os
import struct

from slmp_pcaplib import D, Pcap, TcpSession, dev_short, request, response, udp

p = Pcap()

s = TcpSession(p, "192.168.10.10", 49200, "192.168.10.22", 5002)
s.open()
s.send(True, request("3E", 0x0401, 0x0000, dev_short(0, D) + struct.pack("<H", 1)))
s.send(False, response("3E", data=struct.pack("<H", 1)))
s.send(True, b"\x99\x00" + request("3E", 0x0401, 0x0000)[2:])
s.close()

bad_fixed = bytearray(request("4E", 0x0401, 0x0000, dev_short(0, D) + struct.pack("<H", 1), serial=0x10))
bad_fixed[4] = 0xFF
udp(p, "192.168.10.10", 50020, "192.168.10.23", 5003, bytes(bad_fixed))

too_long = bytearray(request("3E", 0x0401, 0x0000, dev_short(0, D) + struct.pack("<H", 1)))
too_long[7:9] = struct.pack("<H", 0x0100)
udp(p, "192.168.10.10", 50030, "192.168.10.24", 5004, bytes(too_long))

p.write(os.path.join(os.path.dirname(os.path.abspath(__file__)), "slmp_malformed.pcap"))
