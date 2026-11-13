# zeek-slmp

A [Spicy](https://docs.zeek.org/projects/spicy/)-based [Zeek](https://zeek.org) analyzer for
SLMP (SeamLess Message Protocol), the message protocol used by Mitsubishi Electric MELSEC
controllers and other SLMP-compatible devices. It parses the binary encoding of 3E, 4E and
station number extension frames over TCP and UDP and writes `slmp.log`.

The package is meant for research and interoperability: passive visibility into SLMP traffic on
networks you are authorised to monitor. It only reads traffic; it never sends anything.

Author: John B Joseph

## What it parses

- Frame types (binary code only):
  - 3E request/response (subheader `50 00` / `D0 00`)
  - 4E request/response (subheader `54 00` / `D4 00`, with serial number)
  - station number extension request/response (subheader `68 00` / `E8 00`, with serial number
    and extension station number)
- Header: request destination network number, station number, module I/O number, multidrop
  station number, request data length, monitoring timer.
- Command and subcommand for every request. All commands in the manual's command list get a
  name; unknown codes are logged as `unknown-0x....`.
- Device fields decoded for:
  - Device Read `0401` and Device Write `1401`, subcommands `0000`-`0003` (head device, device
    code, number of points);
  - Device Read Random `0403`, subcommands `0000`/`0002` (number of entries and the first
    device);
  - Device Write Random `1402`, subcommands `0000`-`0003` (number of entries and the first
    device).
- Remote Run `1001` mode and clear mode. Remote Stop `1002`, Pause `1003`, Latch Clear `1005`
  and Reset `1006` are logged by name.
- Read Type Name `0101`: model name and model code from the response.
- Responses: end code; for error responses, the command and subcommand echoed by the device.

## slmp.log

One line per request/response pair. 4E and station number extension frames are paired by serial
number; 3E frames (no serial number) are paired in order of arrival on the connection. A request
with no response is logged when the connection ends (`status` = `no_response`); a response with
no matching request is logged on its own (`status` = `no_request`).

| Field | Type | Description |
|---|---|---|
| ts | time | Time of the request (or of the response, if no request was seen) |
| uid, id | string, conn_id | Zeek connection identifiers |
| proto | transport_proto | `tcp` or `udp` |
| frame_type | string | `3E`, `4E` or `station-ext` |
| serial | count | Serial number (4E and station-ext only) |
| network | count | Request destination network number |
| station | count | Request destination station number |
| module_io | string | Request destination module I/O number, hex (for example `0x03ff`) |
| multidrop | count | Request destination multidrop station number |
| ext_station | count | Extension station number (station-ext only) |
| monitoring_timer | count | Monitoring timer in 250 ms units (0 = wait forever) |
| command | string | Command name, for example `Device Read` or `Remote Stop` |
| command_code | string | Command code, hex |
| subcommand | string | Subcommand, hex |
| device | string | Device name, for example `D`, `M`, `X` (decoded device commands only) |
| head_device | count | Head device number as a number |
| address | string | Device and number in the usual notation, decimal or hex by device, for example `D100`, `X20`, `W100` |
| points | count | Number of points; for random read/write, the number of entries |
| run_mode | string | Remote Run mode, hex (`0x0001` forced execution not allowed, `0x0003` allowed) |
| clear_mode | count | Remote Run clear mode (0, 1 or 2) |
| model_name | string | Model name from a Read Type Name response |
| model_code | string | Model code from a Read Type Name response, hex |
| end_code | string | End code, hex; `0x0000` means success |
| status | string | `ok`, `error`, `no_response` or `no_request` |
| rtt | interval | Time from request to response |

Example (from the test trace `testing/Traces/slmp_3e_tcp.pcap`, some columns left out):

```
frame_type command             subcommand device head_device address points end_code status
3E         Read Type Name      0x0000     -      -           -       -      0x0000   ok
3E         Device Read         0x0000     D      100         D100    3      0x0000   ok
3E         Device Write Random 0x0001     M      50          M50     2      0x0000   ok
3E         Remote Run          0x0000     -      -           -       -      0xc059   error
```

The analyzer confirms the protocol after the first complete frame. Parse errors (unknown
subheader, non-zero fixed fields, a length that does not match the data) raise a protocol
violation, which Zeek reports through `analyzer_violation_info` and `analyzer.log`.

## Ports

SLMP has no fixed port: the port is set in each device's parameters. By default the analyzer
is attached to TCP and UDP ports 5000-5009. Change this with:

```zeek
redef SLMP::ports_tcp += { 6000/tcp };
redef SLMP::ports_udp += { 6000/udp };
```

## Installation

With zkg, from a local clone:

```
zkg install ./zeek-slmp
```

Manual build (needs `spicyz`, which ships with Zeek 6 and later, and CMake):

```
mkdir -p build && cd build && cmake .. && cmake --build .
zeek -r capture.pcap ./build/slmp.hlto ./scripts
```

## Tests

```
cd testing && btest -c btest.cfg
```

The test captures in `testing/Traces` are synthetic. Each `.pcap` is generated by the Python
script with the same name (`slmp_3e_tcp.py` writes `slmp_3e_tcp.pcap`, and so on), using
`slmp_pcaplib.py` and the standard library only. No traffic from a real device is included.

| Test | Covers |
|---|---|
| availability | Both analyzers are registered |
| trace-3e-tcp | 3E over TCP: Read Type Name, batch read/write (Q/L and iQ-R formats), random read/write, remote STOP and RUN, an error end code, two frames in one segment, a frame split across segments |
| trace-4e-udp | 4E over UDP: serial number pairing with out-of-order responses, remote PAUSE/latch clear/RESET, a request without a response, a response without a request, a station number extension frame |
| malformed | Unknown subheader, non-zero fixed field, request data length larger than the datagram |

## Sources

The protocol was implemented from the publicly downloadable manual only:

- Mitsubishi Electric, *SLMP Reference Manual*, SH(NA)-080956ENG, revision N (October 2025),
  downloaded 2026-11-13 from
  `https://dl.mitsubishielectric.com/dl/fa/document/manual/plc/sh080956eng/sh080956engn.pdf`,
  SHA-256 `3abef70db23577dded014af0f7fabd5d340284d590ff28dceb4442d8aea70ed4`.
  Chapter 4 (message format) and sections 5.1, 5.2 and 5.6 (command list, device access,
  remote control).

No text from the manual is copied into this repository beyond command names, device names and
numeric codes.

Related work: [nttcom/zeek-parser-CCLinkTSNSLMP](https://github.com/nttcom/zeek-parser-CCLinkTSNSLMP)
parses SLMP frames carried by CC-Link IE TSN on UDP ports 45238/45239 and logs the command and
subcommand. This package covers the MELSEC Ethernet 3E/4E frames on user-configured ports and
decodes device access, remote control and end codes.

The files `cmake/FindSpicyPlugin.cmake`, `testing/Scripts/get-zeek-env`,
`testing/Scripts/diff-remove-timestamps` and `testing/Files/random.seed` come from
[zeek/package-template](https://github.com/zeek/package-template) (BSD-3-Clause).

## Limitations

- ASCII code frames are not parsed; they raise a protocol violation.
- Device extension specification subcommands (`0080`-`0083`), block read/write (`0406`/`1406`),
  monitor registration, label, memory, extend unit, file, remote password and self test
  commands are logged by name and subcommand only; their data is not decoded.
- Random read/write log the first device and the number of entries, not every device.
- Write data and read data values are not logged.
- End codes are logged as numbers. Their meaning depends on the device and is documented in each
  device's manual, so no names are assigned.
- 3E pairing assumes responses arrive in request order on a connection, as the protocol has no
  serial number for 3E. Pipelined 3E requests answered out of order would be mispaired.
- The analyzer was tested only against the synthetic captures in this repository, not against
  traffic from real controllers.
- The station number extension frame was implemented from the manual's format description; it
  is covered by one synthetic test.

## Development note

Parts of this package, including the capture generator scripts, were written with the help of
an AI coding assistant.

## License

BSD-3-Clause, see [LICENSE](LICENSE).
