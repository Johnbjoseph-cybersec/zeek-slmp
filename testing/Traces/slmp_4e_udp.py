#!/usr/bin/env python3
"""Generate slmp_4e_udp.pcap: binary 4E and station number extension frames over UDP.

Synthetic traffic, written by this script (no real device involved).
Covers serial number pairing with responses out of order, remote PAUSE,
latch clear and RESET (the RESET gets no response), an error response that
matches no request, and one station number extension frame addressed to
extension station 200.
"""

import os
import struct

from slmp_pcaplib import D, Pcap, dev_long, dev_short, request, response, udp

p = Pcap()
CLI, SRV = "192.168.10.10", "192.168.10.21"


def to_srv(payload):
    udp(p, CLI, 50010, SRV, 5001, payload, True)


def to_cli(payload):
    udp(p, SRV, 5001, CLI, 50010, payload, False)


# Read Type Name, serial 0x0001.
to_srv(request("4E", 0x0101, 0x0000, serial=0x0001))
to_cli(response("4E", serial=0x0001, data=b"R08CPU".ljust(16, b" ") + struct.pack("<H", 0x4801)))

# Device Read D0 x2 (serial 0x0002) and Remote Pause (serial 0x0003);
# responses come back in reverse order.
to_srv(request("4E", 0x0401, 0x0000, dev_short(0, D) + struct.pack("<H", 2), serial=0x0002))
to_srv(request("4E", 0x1003, 0x0000, struct.pack("<H", 1), serial=0x0003))
to_cli(response("4E", serial=0x0003))
to_cli(response("4E", serial=0x0002, data=struct.pack("<HH", 7, 8)))

# Remote Latch Clear (serial 0x0004).
to_srv(request("4E", 0x1005, 0x0000, struct.pack("<H", 1), serial=0x0004))
to_cli(response("4E", serial=0x0004))

# Station number extension frame: network 1, station 7CH, extension station 200,
# Device Read D10 x1 in iQ-R format (serial 0x0006).
rt = dict(network=1, station=0x7C)
to_srv(request("EXT", 0x0401, 0x0002, dev_long(10, D) + struct.pack("<H", 1), serial=0x0006,
               ext_station=200, **rt))
to_cli(response("EXT", serial=0x0006, command=0x0401, subcommand=0x0002, ext_station=200,
                data=struct.pack("<H", 42), **rt))

# A response whose serial number (0x0099) matches no request.
to_cli(response("4E", serial=0x0099, end_code=0xC051, command=0x0401, subcommand=0x0000))

# Remote Reset (serial 0x0005): no response is sent.
to_srv(request("4E", 0x1006, 0x0000, struct.pack("<H", 1), serial=0x0005))

p.write(os.path.join(os.path.dirname(os.path.abspath(__file__)), "slmp_4e_udp.pcap"))
