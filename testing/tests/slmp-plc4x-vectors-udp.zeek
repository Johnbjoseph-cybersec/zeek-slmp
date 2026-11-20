# @TEST-DOC: PCAPs from the Apache PLC4X SLMP reference vectors (UDP)
#
# @TEST-EXEC: zeek -Cr ${TRACES}/slmp-plc4x-vectors-udp.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: zeek-cut service < conn.log >>output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff slmp.log
