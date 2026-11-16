#!/usr/bin/env python3
"""Generate slmp_recovery.pcap: the analyzer must keep parsing after a bad frame.

Synthetic traffic, written by this script (no real device involved).
1. TCP 5005: a 3E polling loop with a capture gap. The fourth request segment
   is missing from the capture; the pairs before and after it must be logged.
2. TCP 5006: a 3E error response that carries only the end code (no error
   information block), followed by a normal pair.
3. TCP 5007: 7 bytes of non-SLMP data between two valid 3E pairs.
4. TCP 5008: a 3E polling loop where one response is missing from the
   capture. 3E frames have no serial number, so pending requests are
   dropped at the gap instead of being paired with later responses.
"""

import os
import struct

from slmp_pcaplib import D, Pcap, TcpSession, dev_short, request, response

p = Pcap()


def read_d(n):
    return request("3E", 0x0401, 0x0000, dev_short(n, D) + struct.pack("<H", 1))


def ok(v):
    return response("3E", data=struct.pack("<H", v))


# 1. Gap in the client-to-server stream.
s = TcpSession(p, "192.168.20.10", 49300, "192.168.20.21", 5005)
s.open()
for i in range(3):
    s.send(True, read_d(100 + i))
    s.send(False, ok(i))
s.skip(True, len(read_d(103)))       # request for D103 is not in the capture
s.send(False, ok(3))                  # its response is
for i in range(4, 7):
    s.send(True, read_d(100 + i))
    s.send(False, ok(i))
s.close()

# 2. Error response with the end code only (data length 2).
s = TcpSession(p, "192.168.20.10", 49301, "192.168.20.22", 5006)
s.open()
s.send(True, read_d(200))
short_err = b"\xD0\x00" + struct.pack("<BBHB", 0x00, 0xFF, 0x03FF, 0x00) + struct.pack("<HH", 2, 0xC059)
s.send(False, short_err)
s.send(True, read_d(201))
s.send(False, ok(201))
s.close()

# 3. Junk between frames.
s = TcpSession(p, "192.168.20.10", 49302, "192.168.20.23", 5007)
s.open()
s.send(True, read_d(300))
s.send(False, ok(300))
s.send(True, b"\x01\x02\x03\x04\x05\x06\x07" + read_d(301))
s.send(False, ok(301))
s.close()

# 4. Gap in the server-to-client stream.
s = TcpSession(p, "192.168.20.10", 49303, "192.168.20.24", 5008)
s.open()
for i in range(2):
    s.send(True, read_d(400 + i))
    s.send(False, ok(400 + i))
s.send(True, read_d(402))
s.skip(False, len(ok(402)))          # response for D402 is not in the capture
for i in range(3, 5):
    s.send(True, read_d(400 + i))
    s.send(False, ok(400 + i))
s.close()

p.write(os.path.join(os.path.dirname(os.path.abspath(__file__)), "slmp_recovery.pcap"))
