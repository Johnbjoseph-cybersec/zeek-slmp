# @TEST-DOC: 3E frames over TCP: batch and random device access, Read Type Name, remote STOP/RUN, an error end code, pipelined and split frames.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/slmp_3e_tcp.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: zeek-cut service < conn.log >>output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff slmp.log
